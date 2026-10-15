# F-SCANER - Local Setup

These steps run F-SCANER locally on Windows. They use three terminals: MinIO, the FastAPI backend and the Streamlit interface.

> **Security note:** F-SCANER accepts uploaded files for analysis and has no authentication. Run it on `127.0.0.1` only and never expose it to an untrusted network. Analyze suspicious files inside an isolated environment (VM).

## Prerequisites

- Windows 10/11
- [Anaconda or Miniconda](https://docs.conda.io/en/latest/miniconda.html)
- [MinIO server](https://min.io/download) installed and available in your `PATH`

In the commands below, replace `<PROJECT_ROOT>` with the folder where you cloned the repository (for example `C:\Projects\F-SCANER`).

## 0. Create the Python environment (first time only)

From the project root:

```bat
cd <PROJECT_ROOT>
conda env create -f environment.yml
conda activate fscaner
```

The environment is named `fscaner` and its dependencies are listed in `environment.yml`.

## 1. Start MinIO

From the project root:

```bat
cd <PROJECT_ROOT>
minio server .\minio_data --console-address 127.0.0.1:9001
```

The MinIO console is then available at <http://127.0.0.1:9001>. Use your own credentials instead of the defaults, and configure the same credentials for the API (see the README).

## 2. Start the FastAPI backend

Open a second terminal:

```bat
conda activate fscaner
cd <PROJECT_ROOT>\api
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The interactive API documentation is available at <http://127.0.0.1:8000/docs>.

## 3. Start the Streamlit interface

Open a third terminal:

```bat
conda activate fscaner
cd <PROJECT_ROOT>\api
streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

Then open <http://127.0.0.1:8501>.

## Troubleshooting

- **Port already in use:** change `--port` (API) or `--server.port` (Streamlit), and update the API URL used by the interface accordingly.
- **`minio` is not recognized:** add the folder containing `minio.exe` to your `PATH`, or run it with its full path.
- **`conda activate` fails:** open an *Anaconda Prompt* instead of a standard terminal.
- **Environment already exists:** run `conda env update -f environment.yml --prune` to update it.
