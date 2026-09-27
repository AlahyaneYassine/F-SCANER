import os
import json
from pathlib import Path

import numpy as np
import tqdm


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "ember2018"


# Fichiers d'entraînement
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


# Créer le fichier y_train.dat
y_path = os.path.join(DATA_DIR, "y_train.dat")

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
                y_train[idx] = raw.get("label", -1)

            except Exception:
                y_train[idx] = -1

            idx += 1


y_train.flush()


# Vérification
print("\nVérification :")
print(
    f"Labels : "
    f"{ {int(v): int(c) for v, c in zip(*np.unique(y_train, return_counts=True))} }"
)

print("Terminé ✅")