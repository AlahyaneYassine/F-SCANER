# ============================================================
# main.py — FastAPI Chef d'orchestre
# ============================================================
import os
import sys
import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor

from fastapi import (FastAPI, File, UploadFile,
                     HTTPException)
from fastapi.responses import (HTMLResponse,
                                JSONResponse,
                                Response)
from fastapi.middleware.cors import CORSMiddleware

# ── Ajouter api/ au path Python ───────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from config import MAX_FILE_SIZE_MB
from pipeline.static_analyzer  import (
    extract_static_features, is_valid_pe)
from pipeline.dynamic_analyzer import (
    analyze_file_dynamic)
from pipeline.feature_mapper   import (
    map_report_to_features)
from pipeline.predictor        import predict_weighted_vote
from pipeline.storage          import upload_file, list_files
from pipeline.report_generator import generate_report

# ── Application FastAPI ────────────────────────────────────
app = FastAPI(
    title="Détecteur de Malware Hybride ML+DL",
    description="Analyse statique + dynamique avec "
                "5 modèles IA et Weighted Vote",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)


# ── Helpers ────────────────────────────────────────────────
def get_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def run_static(file_bytes):
    """Analyse statique dans un thread."""
    features, err = extract_static_features(file_bytes)
    return features, err


def run_dynamic(file_bytes, filename):
    """Analyse dynamique dans un thread."""
    report, err = analyze_file_dynamic(
        file_bytes, filename)
    return report, err


# ── Endpoints ──────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    """Page principale — interface utilisateur."""
    html_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/health")
async def health():
    """Vérification que l'API fonctionne."""
    return {
        "status" : "ok",
        "message": "API Malware Detector opérationnelle"
    }


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    """
    Endpoint principal — analyse un fichier PE.

    Flux :
    1. Validation du fichier
    2. Analyse statique (lief → EMBER)
    3. Analyse dynamique (VirusTotal)
    4. Weighted Vote (5 modèles)
    5. Stockage MinIO si bénin
    6. Retour résultat JSON complet
    """
    # ── Lecture fichier ────────────────────────────────
    file_bytes = await file.read()
    filename   = file.filename
    file_size  = len(file_bytes)

    # ── Validation taille ──────────────────────────────
    if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"Fichier trop volumineux. "
                   f"Max {MAX_FILE_SIZE_MB}MB")

    # ── Validation PE ──────────────────────────────────
    if not is_valid_pe(file_bytes):
        raise HTTPException(
            status_code=400,
            detail="Fichier invalide — "
                   "seuls les fichiers PE "
                   "(.exe, .dll) sont acceptés")

    sha256 = get_sha256(file_bytes)

    # ── Analyses en parallèle ──────────────────────────
    loop = asyncio.get_event_loop()

    static_task  = loop.run_in_executor(
        executor, run_static, file_bytes)
    dynamic_task = loop.run_in_executor(
        executor, run_dynamic, file_bytes, filename)

    (features_ember, static_err), \
    (dynamic_report, dynamic_err) = await asyncio.gather(
        static_task, dynamic_task)

    # ── Mapping dynamique → CIC-MalMem ────────────────
    features_malmem = None
    if dynamic_report and not dynamic_err:
        features_malmem, map_err = \
            map_report_to_features(dynamic_report)
        if map_err:
            features_malmem = None

    # ── Vérification analyse statique ─────────────────
    if features_ember is None:
        raise HTTPException(
            status_code=500,
            detail=f"Échec analyse statique : "
                   f"{static_err}")

    # ── Weighted Vote ──────────────────────────────────
    prediction = predict_weighted_vote(
        features_ember  = features_ember,
        features_malmem = features_malmem)

    if prediction is None:
        raise HTTPException(
            status_code=500,
            detail="Échec de la prédiction")

    # ── Stockage MinIO si bénin ────────────────────────
    minio_object = None
    if not prediction["is_malware"]:
        minio_object, minio_err = upload_file(
            file_bytes = file_bytes,
            filename   = filename,
            sha256     = sha256,
            confidence = prediction["confidence"])

    # ── Résultat final ─────────────────────────────────
    return JSONResponse({
        "filename"       : filename,
        "sha256"         : sha256,
        "file_size"      : file_size,
        "verdict"        : prediction["verdict"],
        "confidence"     : prediction["confidence"],
        "is_malware"     : prediction["is_malware"],
        "votes"          : prediction["votes"],
        "n_models"       : prediction["n_models"],
        "n_malware_votes": prediction["n_malware_votes"],
        "static_analysis": {
            "status"  : "success",
            "features": 200,
            "error"   : static_err
        },
        "dynamic_analysis": {
            "status"   : "success" if dynamic_report
                         else "failed",
            "error"    : dynamic_err,
            "available": dynamic_report is not None
        },
        "minio_stored" : minio_object is not None,
        "minio_object" : minio_object,
    })


@app.post("/report")
async def download_report(file: UploadFile = File(...)):
    """
    Génère et retourne un rapport PDF complet.
    """
    file_bytes = await file.read()
    filename   = file.filename
    file_size  = len(file_bytes)
    sha256     = get_sha256(file_bytes)

    if not is_valid_pe(file_bytes):
        raise HTTPException(
            status_code=400,
            detail="Fichier PE invalide")

    # ── Analyses ───────────────────────────────────────
    loop = asyncio.get_event_loop()
    static_task  = loop.run_in_executor(
        executor, run_static, file_bytes)
    dynamic_task = loop.run_in_executor(
        executor, run_dynamic, file_bytes, filename)

    (features_ember, _), \
    (dynamic_report, _) = await asyncio.gather(
        static_task, dynamic_task)

    features_malmem = None
    if dynamic_report:
        features_malmem, _ = map_report_to_features(
            dynamic_report)

    prediction = predict_weighted_vote(
        features_ember, features_malmem)

    # ── Génération PDF ─────────────────────────────────
    pdf_bytes = generate_report(
        filename       = filename,
        sha256         = sha256,
        file_size      = file_size,
        prediction     = prediction,
        static_info    = {"size": file_size},
        dynamic_report = dynamic_report)

    return Response(
        content    = pdf_bytes,
        media_type = "application/pdf",
        headers    = {
            "Content-Disposition":
                f'attachment; '
                f'filename="rapport_{filename}.pdf"'
        }
    )


@app.get("/files")
async def list_stored_files():
    """Liste les fichiers bénins stockés dans MinIO."""
    files = list_files()
    return {"files": files, "count": len(files)}


# ── Démarrage ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False)