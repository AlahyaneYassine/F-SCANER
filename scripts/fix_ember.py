import os
import json
from pathlib import Path
import numpy as np
import tqdm
import ember
import ember.features as ef



PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "ember2018"

# ── Patch du bug sklearn ──────────────────────────────────────────────
_orig = ef.SectionInfo.process_raw_features

def _patched(self, raw_obj):
    entry = raw_obj.get('entry', '')
    if isinstance(entry, str):
        raw_obj = dict(raw_obj)
        raw_obj['entry'] = [entry] if entry else []
    return _orig(self, raw_obj)

ef.SectionInfo.process_raw_features = _patched
# ─────────────────────────────────────────────────────────────────────

extractor = ef.PEFeatureExtractor(2)
ndim = extractor.dim

test_jsonl = os.path.join(DATA_DIR, "test_features.jsonl")
X_test_path = os.path.join(DATA_DIR, "X_test.dat")
y_test_path = os.path.join(DATA_DIR, "y_test.dat")

# Compter les lignes d'abord
print("Comptage des lignes test...")
with open(test_jsonl, "r") as f:
    nrows = sum(1 for _ in f)
print(f"  → {nrows} samples trouvés")

# Créer les fichiers .dat
X_test = np.memmap(X_test_path, dtype=np.float32, mode="w+", shape=(nrows, ndim))
y_test = np.memmap(y_test_path, dtype=np.float32, mode="w+", shape=(nrows,))

print("Vectorisation test set...")
with open(test_jsonl, "r") as f:
    for i, line in enumerate(tqdm.tqdm(f, total=nrows)):
        try:
            raw = json.loads(line)
            X_test[i] = extractor.process_raw_features(raw)
            y_test[i] = raw.get("label", -1)
        except Exception as e:
            X_test[i] = np.zeros(ndim)
            y_test[i] = -1

print("Flush sur disque...")
X_test.flush()
y_test.flush()
print("Terminé ! X_test.dat et y_test.dat créés.")