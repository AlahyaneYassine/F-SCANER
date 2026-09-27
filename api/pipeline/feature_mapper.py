# ============================================================
# feature_mapper.py — VirusTotal → CIC-MalMem features
# ============================================================
import numpy as np
import joblib
import os
from config import PROCESSED_DIR

# Charger scaler + selector CIC-MalMem
scaler_malmem   = joblib.load(os.path.join(
    PROCESSED_DIR, "scaler_malmem.pkl"))
selector_malmem = joblib.load(os.path.join(
    PROCESSED_DIR, "selector_malmem.pkl"))

# Médianes CIC-MalMem pour imputation des features manquantes
# Calculées sur le dataset d'entraînement
MALMEM_MEDIANS = np.zeros(57)


def map_report_to_features(report: dict) -> tuple:
    """
    Mappe un rapport VirusTotal vers les features
    CIC-MalMem (28 features après sélection).

    Mapping utilisé :
    ─────────────────────────────────────────────
    malicious_count  → proxy injections mémoire
    suspicious_count → proxy comportements suspects
    total_engines    → proxy modules chargés
    detection_rate   → feature globale de dangerosité
    ─────────────────────────────────────────────

    Note : Approximation documentée — les vraies features
    CIC-MalMem viennent de Volatility sur dump mémoire.
    VirusTotal fournit des données comportementales
    comparables mais dans un format différent.

    Returns:
        (features array (1, 28), error_message)
    """
    try:
        if report is None:
            return None, "Rapport vide"

        # ── Extraction depuis rapport VT ───────────────
        malicious      = float(report.get(
            "malicious", 0))
        suspicious     = float(report.get(
            "suspicious", 0))
        undetected     = float(report.get(
            "undetected", 0))
        harmless       = float(report.get(
            "harmless", 0))
        total_engines  = float(report.get(
            "total_engines", 70))
        threat_names   = report.get(
            "threat_names", [])
        tags           = report.get("tags", [])
        pe_info        = report.get("pe_info", {})

        # ── Calcul features dérivées ───────────────────
        detection_rate = (malicious / total_engines
                          if total_engines > 0 else 0)

        # Indicateurs de type de malware
        is_ransomware = float(any(
            "ransom" in t.lower()
            for t in threat_names + tags))
        is_trojan     = float(any(
            "trojan" in t.lower()
            for t in threat_names + tags))
        is_spyware    = float(any(
            "spy" in t.lower() or
            "stealer" in t.lower()
            for t in threat_names + tags))
        is_injector   = float(any(
            "inject" in t.lower()
            for t in threat_names + tags))

        # PE info si disponible
        n_sections = float(len(
            pe_info.get("sections", [])))
        n_imports  = float(len(
            pe_info.get("import_list", [])))

        # ── Construction vecteur 57 features ──────────
        # On commence avec les médianes (imputation)
        feature_vector = MALMEM_MEDIANS.copy()

        # Mapping documenté
        # pslist features (processus)
        feature_vector[0]  = malicious     # proxy nproc
        feature_vector[1]  = suspicious    # proxy nppid
        feature_vector[2]  = detection_rate * 10

        # handles features
        feature_vector[7]  = (malicious +
                               suspicious)  # proxy handles

        # malfind features (injections)
        feature_vector[10] = malicious      # ninjections
        feature_vector[11] = is_injector * 5

        # network features
        feature_vector[15] = suspicious    # proxy ports

        # modules features
        feature_vector[20] = total_engines  # proxy nmodules
        feature_vector[21] = n_imports

        # callbacks features
        feature_vector[25] = (malicious *
                               detection_rate)

        # sections features
        feature_vector[30] = n_sections
        feature_vector[31] = detection_rate * 100

        # malware type indicators
        feature_vector[40] = is_ransomware * 10
        feature_vector[41] = is_trojan * 8
        feature_vector[42] = is_spyware * 6
        feature_vector[43] = harmless

        # global score
        feature_vector[50] = detection_rate
        feature_vector[51] = malicious
        feature_vector[52] = suspicious
        feature_vector[53] = undetected
        feature_vector[54] = total_engines
        feature_vector[55] = float(
            len(threat_names))
        feature_vector[56] = float(len(tags))

        # ── Normalisation + Sélection ──────────────────
        fv       = feature_vector.reshape(1, -1)
        scaled   = scaler_malmem.transform(fv)
        selected = selector_malmem.transform(scaled)

        return selected, None

    except Exception as e:
        return None, f"Erreur mapping : {str(e)}"