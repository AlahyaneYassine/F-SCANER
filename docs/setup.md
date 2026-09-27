# F-SCANER - Local Setup

## 1. Start MinIO

Install MinIO separately, then start the MinIO server from the project root:

```powershell
cd C:\PFA_Malware
minio server .\minio_data --console-address :9001
```

## 2. Start the FastAPI backend

Open a second terminal:

```powershell
conda activate malware_env
cd C:\PFA_Malware\api
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

## 3. Start the Streamlit interface

Open a third terminal:

```powershell
conda activate malware_env
cd C:\PFA_Malware\api
streamlit run app.py --server.port 8501
```