# ============================================================
# dynamic_analyzer.py — VirusTotal API
# Analyse dynamique basée sur les rapports VirusTotal
# 500 requêtes/jour gratuites — sans vetting
# ============================================================
import requests
import hashlib
import time
import os
from config import VIRUSTOTAL_API_KEY

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_HEADERS  = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "Accept"  : "application/json"
}


def get_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def check_existing_report(sha256: str) -> tuple:
    """
    Vérifie si VirusTotal a déjà un rapport
    pour ce fichier via son SHA256.
    Instantané si fichier connu — pas d'upload.
    """
    try:
        url  = f"{VT_BASE_URL}/files/{sha256}"
        resp = requests.get(
            url, headers=VT_HEADERS, timeout=30)

        if resp.status_code == 200:
            print("✅ Rapport VT existant trouvé")
            return resp.json(), None
        elif resp.status_code == 404:
            return None, "Fichier inconnu — upload requis"
        else:
            return None, f"Erreur VT : {resp.status_code}"

    except Exception as e:
        return None, f"Erreur réseau : {str(e)}"


def upload_file(file_bytes: bytes,
                filename: str) -> tuple:
    """
    Uploade un fichier vers VirusTotal pour analyse.
    Note : les fichiers uploadés sont publics sur VT.
    Utilisé uniquement si le fichier est inconnu.
    """
    try:
        url   = f"{VT_BASE_URL}/files"
        files = {
            "file": (filename, file_bytes,
                     "application/octet-stream")
        }
        resp = requests.post(
            url, headers=VT_HEADERS,
            files=files, timeout=60)

        if resp.status_code == 200:
            data       = resp.json()
            analysis_id = data.get("data", {}).get("id")
            if analysis_id:
                print(f"✅ Fichier uploadé — ID : {analysis_id}")
                return analysis_id, None
            return None, "analysis_id manquant"
        else:
            return None, f"Erreur upload : {resp.text[:200]}"

    except Exception as e:
        return None, f"Erreur upload : {str(e)}"


def get_analysis_result(analysis_id: str) -> tuple:
    """
    Récupère le résultat d'une analyse par son ID.
    Utilisé après upload pour attendre la fin de l'analyse.
    """
    try:
        url  = f"{VT_BASE_URL}/analyses/{analysis_id}"
        resp = requests.get(
            url, headers=VT_HEADERS, timeout=30)

        if resp.status_code == 200:
            return resp.json(), None
        return None, f"Erreur : {resp.status_code}"

    except Exception as e:
        return None, str(e)


def get_file_report(sha256: str) -> tuple:
    """
    Récupère le rapport complet d'un fichier
    après son analyse.
    """
    try:
        url  = f"{VT_BASE_URL}/files/{sha256}"
        resp = requests.get(
            url, headers=VT_HEADERS, timeout=30)

        if resp.status_code == 200:
            return resp.json(), None
        return None, f"Rapport non trouvé : {resp.status_code}"

    except Exception as e:
        return None, str(e)


def analyze_file_dynamic(file_bytes: bytes,
                          filename: str) -> tuple:
    """
    Flux complet d'analyse dynamique via VirusTotal.

    Étape 1 : Vérifier si rapport existant (SHA256)
              → Instantané si fichier connu
    Étape 2 : Si inconnu → Upload + attendre analyse
              → ~30-60 secondes
    Étape 3 : Retourner rapport JSON complet

    Returns:
        (rapport_dict, error_message)
    """
    sha256 = get_sha256(file_bytes)
    print(f"SHA256 : {sha256[:16]}...")

    # ── Étape 1 : Check cache ──────────────────────────
    existing, err = check_existing_report(sha256)
    if existing:
        return _extract_stats(existing), None

    # ── Étape 2 : Upload fichier ───────────────────────
    print("Fichier inconnu — upload vers VirusTotal...")
    analysis_id, err = upload_file(file_bytes, filename)
    if err:
        return None, err

    # ── Étape 3 : Polling résultat ─────────────────────
    max_wait = 120  # 2 minutes max
    elapsed  = 0
    interval = 15  # vérifier toutes les 15 secondes

    while elapsed < max_wait:
        time.sleep(interval)
        elapsed += interval
        print(f"Attente analyse VT... {elapsed}s/{max_wait}s")

        result, err = get_analysis_result(analysis_id)
        if err:
            continue

        status = result.get("data", {}).get(
            "attributes", {}).get("status", "")

        if status == "completed":
            print("✅ Analyse VT terminée")
            # Récupérer le rapport complet via SHA256
            report, err = get_file_report(sha256)
            if report:
                return _extract_stats(report), None
            return None, err

        elif status == "failed":
            return None, "Analyse VT échouée"

    return None, "Timeout — analyse VT trop longue"


def _extract_stats(vt_report: dict) -> dict:
    """
    Extrait les statistiques clés du rapport VT.
    Normalise le format pour feature_mapper.py.
    """
    try:
        attrs = vt_report.get(
            "data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            # Scores de détection
            "malicious"     : stats.get(
                "malicious", 0),
            "suspicious"    : stats.get(
                "suspicious", 0),
            "undetected"    : stats.get(
                "undetected", 0),
            "harmless"      : stats.get(
                "harmless", 0),
            "total_engines" : sum(stats.values()),

            # Métadonnées
            "names"    : attrs.get(
                "meaningful_name", ""),
            "tags"     : attrs.get("tags", []),
            "type_tags": attrs.get(
                "type_tags", []),

            # Comportement
            "threat_names"    : list(set([
                v.get("result", "")
                for v in attrs.get(
                    "last_analysis_results",
                    {}).values()
                if v.get("result")
            ]))[:5],

            # PE info si disponible
            "pe_info": attrs.get(
                "pe_info", {}),

            # Source
            "_source": "virustotal"
        }

    except Exception as e:
        print(f"⚠️ Extraction stats VT : {e}")
        return {
            "malicious"     : 0,
            "suspicious"    : 0,
            "undetected"    : 0,
            "harmless"      : 0,
            "total_engines" : 0,
            "_source"       : "virustotal_error"
        }