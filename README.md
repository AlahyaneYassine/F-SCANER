# F-SCANER

### Hybrid Malware Detection & Analysis Platform

> **Academic cybersecurity project — EMSI — 2025/2026**

F-SCANER is an academic cybersecurity prototype for the detection and analysis of potentially malicious Windows PE files.

The platform combines **static PE analysis**, **Machine Learning**, **Deep Learning**, **VirusTotal enrichment**, **Weighted Ensemble Voting**, **PDF reporting**, and **local object storage** into a unified analysis workflow.

The project was designed to explore whether combining heterogeneous ML/DL models can provide a more robust malware classification pipeline than relying on a single model.

---

## Table of Contents

- [Overview](#overview)
- [Key Highlights](#key-highlights)
- [Objectives](#objectives)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Detection Pipeline](#detection-pipeline)
- [Machine Learning & Deep Learning](#machine-learning--deep-learning)
- [Datasets](#datasets)
- [Experimental Results](#experimental-results)
- [Explainability](#explainability)
- [Application Stack](#application-stack)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Platform](#running-the-platform)
- [API](#api)
- [Security & Privacy](#security--privacy)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Academic Context](#academic-context)
- [Authors](#authors)
- [License](#license)

---

# Overview

Traditional signature-based malware detection can struggle with previously unseen or modified malware, particularly when samples use techniques such as obfuscation, packing, or polymorphism.

F-SCANER explores a **hybrid detection approach** combining five model families:

- Random Forest
- XGBoost
- LightGBM
- CNN1D
- FT-Transformer

The models are trained and evaluated using two complementary malware-analysis datasets:

- **EMBER 2018** — static PE features
- **CIC-MalMem 2022** — memory-based malware features

During inference, predictions from the available models are aggregated through a **Weighted Vote** mechanism to produce a final classification and confidence score.

The application layer integrates:

- **FastAPI** for the backend REST API
- **Streamlit** for the user interface
- **MinIO** for local object storage
- **VirusTotal** for external enrichment
- **ReportLab** for PDF report generation
- **SHAP** for model explainability

F-SCANER is an **academic research and demonstration prototype**, not a commercial antivirus product.

---

# Key Highlights

| Component | Description |
|---|---|
| Detection | Hybrid ML + DL malware classification |
| ML models | Random Forest, XGBoost, LightGBM |
| DL models | CNN1D, FT-Transformer |
| Static analysis | EMBER + LIEF-based PE analysis |
| External enrichment | VirusTotal |
| Ensemble | Hard Vote, Soft Vote, Weighted Vote |
| Main runtime strategy | Weighted Vote |
| Interface | Streamlit |
| Backend | FastAPI |
| Storage | MinIO |
| Reporting | PDF with ReportLab |
| Explainability | SHAP |
| Supported files | `.exe`, `.dll` |
| Maximum upload size | 200 MB |
| Project status | Academic prototype |

---

# Objectives

The main objectives of F-SCANER are to:

1. Explore hybrid Machine Learning and Deep Learning approaches for malware detection.
2. Compare several classification algorithms on established malware datasets.
3. Combine heterogeneous models using ensemble strategies.
4. Provide a usable interface for submitting PE files.
5. Enrich local analysis with VirusTotal information when available.
6. Produce an interpretable confidence score and individual model votes.
7. Generate a structured PDF analysis report.
8. Store files classified as benign using local object storage.
9. Evaluate the limitations of combining static and external malware-analysis information.

---

# How It Works

F-SCANER can be understood through two complementary workflows.

## 1. Offline Research Pipeline

The experimental pipeline is used to prepare data, train models and evaluate ensemble strategies.

```text
              Datasets
                 ↓
        EDA & Preprocessing
                 ↓
           Model Training
                 ↓
          Model Evaluation
                 ↓
      Hard / Soft / Weighted Vote
```

## 2. Application Runtime

The deployed prototype follows this flow:

```text
User
 ↓
Streamlit UI
 ↓
FastAPI
 ├── Static Analysis (EMBER + LIEF)
 └── VirusTotal Enrichment
          ↓
    Feature Mapping
          ↓
      ML / DL Models
          ↓
     Weighted Vote
      ↙    ↓    ↘
 Verdict  PDF  MinIO
             Report  (Benign only)
```

---

# Architecture

The current platform is organized into several functional components.

## Frontend

**Streamlit** provides the user-facing interface.

It allows the user to:

- upload a PE file
- launch an analysis
- visualize the verdict
- view confidence
- inspect model votes
- access analysis information
- generate a PDF report

## Backend

**FastAPI** exposes the main application services:

- file validation
- static analysis
- VirusTotal enrichment
- prediction
- ensemble aggregation
- report generation
- MinIO interaction

## Static Analysis

The static analysis layer uses:

- EMBER feature extraction
- LIEF-based PE parsing as an additional/manual feature path

The analysis does not execute the submitted executable.

## External Enrichment

VirusTotal can provide information associated with the submitted file hash or uploaded sample.

## Prediction Engine

The prediction engine loads the trained ML/DL models and combines their outputs.

## Storage

MinIO is used as local object storage.

The current implementation archives only files classified as benign.

---

# Detection Pipeline

## Step 1 — File Validation

The API validates the uploaded file before analysis.

The current application accepts:

```text
.exe
.dll
```

Maximum configured size:

```text
200 MB
```

The system also verifies the PE file signature.

---

## Step 2 — SHA-256 Calculation

A SHA-256 hash is calculated for the submitted file.

The hash is used for:

- file identification
- traceability
- VirusTotal lookup
- report generation

---

## Step 3 — Static Analysis

F-SCANER extracts static information from the PE file.

The main EMBER pipeline generates a feature representation which is then processed using the project's preprocessing artifacts.

A manual LIEF-based pipeline provides additional PE-related information such as:

- file size
- entropy
- PE header information
- optional header information
- number of sections
- section sizes
- section entropy
- imports
- exports
- byte histogram

---

## Step 4 — VirusTotal Enrichment

The application can query VirusTotal using the SHA-256 hash.

If a report already exists, it can be retrieved.

If the file is not known, the current implementation can upload it and poll the resulting analysis.

The integration extracts information such as:

- malicious detections
- suspicious detections
- harmless results
- undetected results
- engine count
- threat names
- tags
- PE-related information

> **Important:** VirusTotal enrichment is an external service and is not equivalent to a locally controlled malware sandbox.

---

## Step 5 — CIC-MalMem Feature Mapping

The application maps selected VirusTotal information to a CIC-MalMem-like feature representation.

This step is an **experimental approximation**.

It does not reproduce native memory-dump feature extraction with Volatility.

This distinction is important when interpreting the runtime architecture and experimental results.

---

## Step 6 — Model Prediction

The prediction engine evaluates the available representations with the five model families:

```text
Random Forest
XGBoost
LightGBM
CNN1D
FT-Transformer
```

Each model produces a probability and an associated binary vote according to its configured threshold.

---

## Step 7 — Weighted Vote

The final decision is obtained by aggregating the model outputs.

The EMBER validation-derived weights currently used by the application are:

| Model | Weight |
|---|---:|
| Random Forest | 0.9470 |
| XGBoost | 1.0000 |
| LightGBM | 0.9851 |
| CNN1D | 0.9641 |
| FT-Transformer | 0.9481 |

The final confidence is computed from the weighted model probabilities.

The current decision rule is:

```text
Confidence >= 0.50  → MALWARE
Confidence <  0.50  → BENIN
```

---

## Step 8 — Results and Storage

The application returns:

- final verdict
- confidence
- individual model votes
- number of models
- number of malware votes
- file hash
- file information
- analysis information

A PDF report can also be generated.

When the final verdict is benign, the file can be archived in MinIO.

---

# Machine Learning & Deep Learning

F-SCANER uses five model families.

## Random Forest

A tree-based ensemble classifier used for malware classification.

## XGBoost

A gradient boosting model used for high-performance tabular classification.

## LightGBM

A gradient boosting framework used as another tree-based classifier.

## CNN1D

A one-dimensional convolutional neural network designed to process the selected feature representation.

The architecture includes convolutional blocks, batch normalization, pooling, dropout and dense layers.

## FT-Transformer

A Transformer-based architecture adapted to tabular feature data.

The project implementation uses feature tokenization, a CLS token and Transformer blocks.

---

# Decision Thresholds

Thresholds were optimized during the experimental phase.

| Model | EMBER | CIC-MalMem |
|---|---:|---:|
| Random Forest | 0.500 | 0.500 |
| XGBoost | 0.500 | 0.500 |
| LightGBM | 0.500 | 0.500 |
| CNN1D | 0.478 | 0.397 |
| FT-Transformer | 0.414 | 0.100 |

These thresholds convert model probabilities into individual classification votes.

---

# Datasets

## EMBER 2018

EMBER is used for static Windows PE malware detection.

The project report describes approximately:

```text
~1 million samples
2381 original features
```

The experimental pipeline performs preprocessing and feature selection before model training.

The final EMBER pipeline uses:

```text
200 selected features
```

---

## CIC-MalMem 2022

CIC-MalMem is used for memory-based malware classification.

The project report describes approximately:

```text
~58,000 memory captures
90 original features
```

The experimental pipeline applies preprocessing and feature selection to the dataset.

---

## Dataset Policy

The original datasets are **not included in this Git repository**.

Reasons include:

- dataset size
- reproducibility requirements
- distribution considerations
- repository size constraints

The required data must therefore be prepared locally before reproducing the complete experimentation workflow.

---

# Experimental Results

The principal reported result for the EMBER test set is:

| Strategy | F1-score | AUC-ROC |
|---|---:|---:|
| Hard Vote | 0.9564 | 0.9796 |
| Soft Vote | 0.9591 | 0.9907 |
| **Weighted Vote** | **0.9592** | **0.9907** |

For CIC-MalMem, the reported fusion results are:

| Strategy | F1-score | AUC-ROC |
|---|---:|---:|
| Hard Vote | 1.0000 | 1.0000 |
| Soft Vote | 1.0000 | 1.0000 |
| Weighted Vote | 1.0000 | 1.0000 |

The EMBER Weighted Vote test set contains both false positives and false negatives, demonstrating that the classifier is not perfect.

The project report explicitly notes that the perfect CIC-MalMem results should be interpreted cautiously and should not be considered evidence of perfect generalization to unseen malware.

> **Important:** these values are experimental benchmark results on the project's evaluation datasets. They should not be interpreted as guaranteed real-world detection rates.

---

# Results Artifacts

The `results/` directory contains the main experimental outputs.

Examples include:

```text
results/
├── dl_results_final.csv
├── ml_results_final.csv
├── ml_results_comparison.csv
├── fusion_results.csv
├── fusion_comparison_full.csv
├── weighted_vote_weights.json
├── fusion_confusion_matrices.png
├── fusion_strategies_comparison.png
├── hardvote_distribution.png
├── eda_ember_distribution.png
├── eda_malmem_distribution.png
├── eda_malmem_correlation.png
├── shap_ranking_ember.csv
├── shap_ranking_malmem.csv
└── shap_*.png
```

Large binary/numerical artifacts are intentionally excluded from Git.

---

# Explainability

F-SCANER uses **SHAP** during the model analysis phase.

SHAP was used to investigate feature importance for the tree-based models.

The current production reporting path focuses on the XGBoost EMBER model for sample-level explanation.

Broader SHAP analyses are available in the experimental results.

---

# Application Stack

| Layer | Technology |
|---|---|
| Programming language | Python |
| Frontend | Streamlit |
| Backend | FastAPI |
| API server | Uvicorn |
| Static PE analysis | EMBER + LIEF |
| ML | scikit-learn, XGBoost, LightGBM |
| DL | TensorFlow / Keras |
| Explainability | SHAP |
| External enrichment | VirusTotal API |
| Object storage | MinIO |
| PDF generation | ReportLab |
| Data processing | NumPy, Pandas, SciPy |
| Experimentation | Jupyter |

---

# Repository Structure

```text
F-SCANER/
│
├── api/
│   ├── app.py
│   ├── config.py
│   ├── main.py
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── dynamic_analyzer.py
│   │   ├── feature_mapper.py
│   │   ├── predictor.py
│   │   ├── report_generator.py
│   │   ├── static_analyzer.py
│   │   └── storage.py
│   └── templates/
│       └── index.html
│
├── docs/
│   ├── setup.md
│   └── report/
│       └── Chapitre1_PFA.docx
│
├── notebooks/
│   ├── Phase1_EDA_Nettoyage.ipynb
│   ├── Phase2_Modeles_ML.ipynb
│   ├── Phase3_Modeles_DL.ipynb
│   └── Phase4_Hard_Vote.ipynb
│
├── results/
│   ├── *.csv
│   ├── *.json
│   └── *.png
│
├── scripts/
│   ├── fix_ember.py
│   ├── fix_xtrain.py
│   └── fix_ytrain.py
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

# Local-Only Resources

The following directories may exist locally but are intentionally excluded from version control:

```text
data/
models/
malware_files_testing/
.ipynb_checkpoints/
anaconda_projects/
```

### `data/`

Contains local datasets and processed numerical artifacts.

### `models/`

Contains trained ML/DL model files.

### `malware_files_testing/`

Contains local malware test samples.

Malware samples are **not intended to be published in this repository**.

### Why are they excluded?

These resources can be very large or security-sensitive.

Keeping them outside Git makes the repository:

- lighter
- safer
- easier to clone
- easier to maintain

---

# Installation

## Requirements

Recommended environment:

```text
Python 3.10+
Conda
```

Create the Conda environment:

```powershell
conda create -n malware_env python=3.10
conda activate malware_env
```

Install the project dependencies:

```powershell
pip install -r requirements.txt
```

---

# Configuration

The project uses environment variables for secrets and local configuration.

Create:

```text
api/.env
```

based on:

```text
.env.example
```

Example configuration:

```env
VIRUSTOTAL_API_KEY=your_api_key_here

MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=your_access_key
MINIO_SECRET_KEY=your_secret_key
MINIO_BUCKET=fscaner
```

Optional paths can also be configured through environment variables:

```env
MODEL_DIR=
PROCESSED_DIR=
```

The application provides local defaults for these paths.

> **Never commit `api/.env` to Git.**

---

# Running the Platform

The complete local platform requires three services/processes.

## Terminal 1 — MinIO

Install MinIO separately.

From the project root:

```powershell
cd C:\PFA_Malware
minio server .\minio_data --console-address :9001
```

MinIO endpoints:

```text
API:
http://localhost:9000

Console:
http://localhost:9001
```

---

## Terminal 2 — FastAPI

```powershell
conda activate malware_env
cd C:\PFA_Malwarepi

python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

API:

```text
http://localhost:8000
```

Swagger documentation:

```text
http://localhost:8000/docs
```

---

## Terminal 3 — Streamlit

```powershell
conda activate malware_env
cd C:\PFA_Malwarepi

streamlit run app.py --server.port 8501
```

Interface:

```text
http://localhost:8501
```

---

# API

F-SCANER exposes the following main endpoints.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Application entry point |
| `GET` | `/health` | Health check |
| `POST` | `/predict` | Analyze and classify a PE file |
| `POST` | `/report` | Analyze and generate a PDF report |
| `GET` | `/files` | List stored benign files |

Interactive Swagger documentation is available at:

```text
http://localhost:8000/docs
```

---

## `/predict`

Example:

```python
import requests

url = "http://localhost:8000/predict"

with open("sample.exe", "rb") as file:
    response = requests.post(
        url,
        files={
            "file": (
                "sample.exe",
                file,
                "application/octet-stream"
            )
        },
        timeout=700
    )

print(response.json())
```

A typical response contains information such as:

```json
{
    "filename": "sample.exe",
    "sha256": "...",
    "size": 123456,
    "verdict": "BENIN",
    "confidence": 40.5,
    "is_malware": false,
    "votes": [],
    "n_models": 5,
    "n_malware_votes": 1
}
```

The exact response structure may evolve with the implementation.

---

# Security & Privacy

F-SCANER is designed to process potentially malicious files.

The following precautions are therefore important.

## Do not commit malware samples

Never add real malware binaries or malware archives to the Git repository.

The repository excludes:

```text
malware_files_testing/
*.exe
*.dll
*.bin
*.7z
*.rar
```

---

## Protect credentials

Never commit:

```text
api/.env
```

API keys, passwords and storage credentials must remain local.

---

## VirusTotal privacy

The current application can upload previously unknown files to VirusTotal.

Accordingly:

> **Do not submit confidential, proprietary or sensitive binaries to VirusTotal.**

Only upload files when you have the necessary authorization.

VirusTotal should therefore be considered an external analysis service, not a private local sandbox.

---

## MinIO storage

The current application stores files classified as benign in MinIO.

The MinIO deployment described in this repository is intended as a **local object-storage component**.

It should not be considered a production cloud-storage deployment.

---

## Production security

The current prototype is designed for local academic use.

A production deployment would require additional security controls such as:

- authentication
- authorization
- restricted CORS origins
- secure TLS configuration
- isolated file processing
- resource limits
- audit logging
- secure object-storage policies
- malware-analysis sandboxing

---

# Limitations

F-SCANER is an academic prototype and has several limitations.

## No native malware sandbox

The system does not execute uploaded malware in a dedicated local sandbox.

VirusTotal is used as an external enrichment mechanism.

---

## CIC-MalMem runtime approximation

The runtime application does not extract the original CIC-MalMem memory features from live memory dumps.

Instead, selected VirusTotal information is mapped to an approximate representation.

This is a research approximation and should not be confused with native memory-forensics analysis.

---

## Dataset generalization

The benchmark results are based on EMBER 2018 and CIC-MalMem 2022.

They do not establish guaranteed performance against:

- zero-day malware
- unseen malware families
- heavily obfuscated samples
- adversarial samples
- real-world enterprise environments

---

## Perfect CIC-MalMem benchmark results

The reported perfect CIC-MalMem results should be interpreted cautiously.

They are benchmark observations rather than proof of perfect malware detection.

---

## External service dependency

VirusTotal availability, quotas and API behavior can affect the enrichment component.

---

## Explainability scope

The current runtime explanation focuses on XGBoost/EMBER SHAP analysis.

Equivalent production explanations are not currently exposed for every model.

---

## Infrastructure

The prototype does not currently provide:

- multi-user authentication
- relational database management
- enterprise SIEM integration
- production cloud deployment
- dedicated sandbox infrastructure
- large-scale distributed inference

---

# Future Improvements

Potential future developments include:

### Detection

- native memory analysis using Volatility
- improved behavioral analysis
- dedicated malware sandboxing
- broader dataset coverage
- evaluation on newer malware families
- adversarial robustness testing

### Machine Learning

- additional model architectures
- calibration of confidence scores
- improved feature engineering
- cross-dataset validation
- automated model versioning

### Explainability

- SHAP integration for additional models
- richer per-feature explanations
- interactive explanation dashboards

### Platform

- authentication and authorization
- analysis history
- database integration
- SIEM integration
- cloud deployment
- asynchronous job processing
- monitoring and logging

### User Evaluation

- structured usability testing
- larger user studies
- SOC analyst feedback
- researcher-oriented workflows

---

# Academic Context

F-SCANER was developed as an academic project at:

**École Marocaine des Sciences de l'Ingénieur (EMSI)**

Academic year:

**2025 / 2026**

The project investigates a hybrid approach for malware detection and intelligent storage of files classified as benign using Machine Learning and Deep Learning.

The academic work covers:

- cybersecurity
- malware detection
- Machine Learning
- Deep Learning
- ensemble learning
- static PE analysis
- explainable AI
- API development
- object storage

---

# Project Status

**Status: Academic Prototype**

The current version demonstrates an end-to-end malware-analysis workflow combining:

```text
PE File
   ↓
Static Analysis
   ↓
External Enrichment
   ↓
ML / DL Prediction
   ↓
Weighted Ensemble
   ↓
Verdict + Confidence
   ↓
Report / Storage
```

The platform is functional for research and demonstration purposes but is not intended to replace a production antivirus, EDR, sandbox or SOC platform.

---

# Authors

**Alahyane Yassine**

**EMSI — 2025/2026**

---

# License

No open-source license has been defined for this repository yet.

Third-party libraries, datasets and external services remain subject to their respective licenses and terms of use.
