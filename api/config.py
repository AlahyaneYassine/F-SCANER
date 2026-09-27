# ============================================================
# F-SCANER - Centralized configuration
# ============================================================

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = Path(__file__).resolve().parent / ".env"

load_dotenv(ENV_FILE)





# VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_MAX_WAIT = 120
VT_POLL_INTERVAL = 15


# MinIO
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "fscaner")


# Project paths
MODEL_DIR = Path(
    os.getenv("MODEL_DIR", str(PROJECT_ROOT / "models"))
)

PROCESSED_DIR = Path(
    os.getenv("PROCESSED_DIR", str(PROJECT_ROOT / "data" / "processed"))
)


# Analysis parameters
MAX_FILE_SIZE_MB = 200
ANALYSIS_TIMEOUT = 600
POLLING_INTERVAL = 30



# Weighted Vote thresholds
THRESHOLDS = {
    "RF_malmem": 0.5,
    "RF_ember": 0.5,
    "XGB_malmem": 0.5,
    "XGB_ember": 0.5,
    "LGB_malmem": 0.5,
    "LGB_ember": 0.5,
    "CNN_malmem": 0.397,
    "CNN_ember": 0.478,
    "FT_malmem": 0.100,
    "FT_ember": 0.414,
}


WEIGHTS_EMBER = {
    "RF": 0.9470,
    "XGBoost": 1.0000,
    "LGB": 0.9851,
    "CNN1D": 0.9641,
    "FT": 0.9481,
}


WEIGHTS_MALMEM = {
    "RF": 0.9999,
    "XGBoost": 1.0000,
    "LGB": 1.0000,
    "CNN1D": 1.0000,
    "FT": 1.0000,
}


WEIGHTS_MALMEM_VT = {
    "RF": 0.5,
    "XGBoost": 0.5,
    "LGB": 0.5,
    "CNN1D": 0.5,
    "FT": 0.5,
}
