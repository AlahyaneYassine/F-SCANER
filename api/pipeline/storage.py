# ============================================================
# storage.py — Stockage MinIO
# ============================================================
from minio import Minio
from minio.error import S3Error
import io
from datetime import datetime
from config import (MINIO_ENDPOINT, MINIO_ACCESS_KEY,
                    MINIO_SECRET_KEY, MINIO_BUCKET)

# ── Connexion MinIO ────────────────────────────────────────
client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False
)

def ensure_bucket():
    """Crée le bucket s'il n'existe pas."""
    try:
        if not client.bucket_exists(MINIO_BUCKET):
            client.make_bucket(MINIO_BUCKET)
            print(f"✅ Bucket '{MINIO_BUCKET}' créé")
        else:
            print(f"✅ Bucket '{MINIO_BUCKET}' existe")
    except S3Error as e:
        print(f"❌ Erreur bucket : {e}")

# Vérifier bucket au démarrage
ensure_bucket()

def upload_file(file_bytes: bytes,
                filename: str,
                sha256: str,
                confidence: float) -> tuple:
    """
    Upload un fichier bénin dans MinIO avec métadonnées.

    Returns:
        (object_name, error_message)
    """
    try:
        # Nom unique dans MinIO
        timestamp   = datetime.now().strftime(
            "%Y%m%d_%H%M%S")
        object_name = f"benin/{timestamp}_{filename}"

        # Métadonnées
        metadata = {
            "x-amz-meta-filename"  : filename,
            "x-amz-meta-sha256"    : sha256,
            "x-amz-meta-confidence": str(confidence),
            "x-amz-meta-date"      : datetime.now(
                ).isoformat(),
            "x-amz-meta-verdict"   : "BENIN",
        }

        # Upload
        client.put_object(
            bucket_name  = MINIO_BUCKET,
            object_name  = object_name,
            data         = io.BytesIO(file_bytes),
            length       = len(file_bytes),
            metadata     = metadata,
        )

        return object_name, None

    except S3Error as e:
        return None, f"Erreur MinIO : {str(e)}"
    except Exception as e:
        return None, f"Erreur upload : {str(e)}"


def list_files() -> list:
    """Liste tous les fichiers bénins stockés."""
    try:
        objects = client.list_objects(
            MINIO_BUCKET, prefix="benin/",
            recursive=True)
        files = []
        for obj in objects:
            files.append({
                "name"        : obj.object_name,
                "size"        : obj.size,
                "last_modified": str(obj.last_modified),
            })
        return files
    except S3Error as e:
        print(f"Erreur listing : {e}")
        return []