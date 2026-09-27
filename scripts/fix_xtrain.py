import os
import json
from pathlib import Path

import numpy as np
import tqdm
import ember.features as ef

from sklearn.feature_extraction import FeatureHasher


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "ember2018"


# ── Patch bug sklearn ─────────────────────────────────────────────
_orig = ef.SectionInfo.process_raw_features


def _patched(self, raw_obj):
    entry = raw_obj.get("entry", "")
    if isinstance(entry, str):
        raw_obj = dict(raw_obj)
        raw_obj["entry"] = [entry] if entry else []
    return _orig(self, raw_obj)


ef.SectionInfo.process_raw_features = _patched
# ─────────────────────────────────────────────────────────────────


extractor = ef.PEFeatureExtractor(2)
ndim = extractor.dim


train_files = [
    os.path.join(DATA_DIR, f"train_features_{i}.jsonl")
    for i in range(6)
]


# Compter les lignes
nrows = 0
for f in train_files:
    with open(f, "r") as fh:
        nrows += sum(1 for _ in fh)

print(f"Total samples : {nrows}")


# Créer les fichiers
X_path = os.path.join(DATA_DIR, "X_train.dat")
y_path = os.path.join(DATA_DIR, "y_train.dat")

X_train = np.memmap(
    X_path,
    dtype=np.float32,
    mode="w+",
    shape=(nrows, ndim),
)

y_train = np.memmap(
    y_path,
    dtype=np.float32,
    mode="w+",
    shape=(nrows,),
)


idx = 0

for fpath in train_files:
    print(f"Traitement {os.path.basename(fpath)}...")

    with open(fpath, "r") as fh:
        for line in tqdm.tqdm(fh):
            try:
                raw = json.loads(line)

                X_train[idx] = extractor.process_raw_features(raw)
                y_train[idx] = raw.get("label", -1)

            except Exception:
                X_train[idx] = np.zeros(ndim)
                y_train[idx] = -1

            idx += 1


X_train.flush()
y_train.flush()


# Vérification immédiate
print("\nVérification :")
print(f"X_train min/max : {X_train.min():.4f} / {X_train.max():.4f}")
print(f"Non-zero        : {np.count_nonzero(X_train)}")
print(
    f"Labels : "
    f"{ {int(v): int(c) for v, c in zip(*np.unique(y_train, return_counts=True))} }"
)

print("Terminé ✅")