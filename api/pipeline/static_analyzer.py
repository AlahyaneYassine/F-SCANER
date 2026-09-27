# ============================================================
# static_analyzer.py — Double pipeline sécuritaire
# ============================================================
import os
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

# ── Patch NumPy compatibility ──────────────────────────────
if not hasattr(np, 'int'):
    np.int     = int
if not hasattr(np, 'float'):
    np.float   = float
if not hasattr(np, 'complex'):
    np.complex = complex
if not hasattr(np, 'bool'):
    np.bool    = bool
if not hasattr(np, 'object'):
    np.object  = object
if not hasattr(np, 'str'):
    np.str     = str

from config import PROCESSED_DIR

# ── Chargement scaler + selector ───────────────────────────
scaler_ember   = joblib.load(os.path.join(
    PROCESSED_DIR, "scaler_ember.pkl"))
selector_ember = joblib.load(os.path.join(
    PROCESSED_DIR, "selector_ember.pkl"))


def apply_lief_patch():
    """Patch de compatibilité lief 0.17 avec ember."""
    try:
        import lief
        patches = [
            'bad_format', 'bad_file', 'pe_error',
            'read_out_of_bound', 'parser_error',
            'conversion_error', 'type_error',
            'not_found', 'not_implemented',
            'corrupted', 'integrity_error',
            'builder_error',
        ]
        for attr in patches:
            if not hasattr(lief, attr):
                setattr(lief, attr, Exception)
        return True
    except Exception as e:
        print(f"⚠️ Patch lief échoué : {e}")
        return False


apply_lief_patch()

try:
    import ember
    import ember.features as ef

    if not getattr(ef.SectionInfo, '_patched', False):
        _orig_section = \
            ef.SectionInfo.process_raw_features

        def _patched_section(self, raw_obj):
            entry = raw_obj.get('entry', '')
            if isinstance(entry, str):
                raw_obj          = dict(raw_obj)
                raw_obj['entry'] = (
                    [entry] if entry else [])
            return _orig_section(self, raw_obj)

        ef.SectionInfo.process_raw_features = \
            _patched_section
        ef.SectionInfo._patched = True

    extractor       = ef.PEFeatureExtractor(2)
    EMBER_AVAILABLE = True
    print("✅ Pipeline EMBER complet chargé")

except Exception as e:
    EMBER_AVAILABLE = False
    print(f"⚠️ ember non disponible : {e}")


def is_valid_pe(file_bytes: bytes) -> bool:
    """Vérifie que le fichier est bien un PE valide."""
    return (len(file_bytes) > 2 and
            file_bytes[:2] == b'MZ')


def extract_static_features_ember(file_bytes: bytes):
    """Pipeline EMBER complet — lief 0.17 patché."""
    try:
        raw_features = extractor.feature_vector(
            file_bytes)
        raw_features = np.array(
            raw_features, dtype=np.float32)

        if raw_features is None or \
                len(raw_features) == 0:
            return None, "Extraction EMBER échouée"

        raw      = raw_features.reshape(1, -1)
        scaled   = scaler_ember.transform(raw)
        selected = selector_ember.transform(scaled)
        return selected, None

    except Exception as e:
        return None, str(e)


def extract_static_features_manual(file_bytes: bytes):
    """Extraction manuelle via lief — fallback."""
    try:
        import lief

        binary = lief.parse(file_bytes)
        if binary is None:
            return None, \
                "lief ne peut pas parser ce fichier"

        features = []

        features.append(float(len(file_bytes)))
        byte_counts = np.bincount(
            np.frombuffer(file_bytes, dtype=np.uint8),
            minlength=256)
        total   = len(file_bytes)
        probs   = byte_counts / total
        entropy = -np.sum(
            probs * np.log2(probs + 1e-10))
        features.append(float(entropy))

        try:
            h = binary.header
            features.extend([
                float(int(h.machine)),
                float(int(h.numberof_sections)),
                float(int(h.time_date_stamps)),
                float(int(h.numberof_symbols)),
                float(int(h.sizeof_optional_header)),
                float(int(h.characteristics)),
            ])
        except Exception:
            features.extend([0.0] * 6)

        try:
            opt = binary.optional_header
            features.extend([
                float(int(opt.magic)),
                float(int(opt.sizeof_code)),
                float(int(
                    opt.sizeof_initialized_data)),
                float(int(
                    opt.sizeof_uninitialized_data)),
                float(int(opt.addressof_entrypoint)),
                float(int(opt.baseof_code)),
                float(int(opt.imagebase)),
                float(int(opt.section_alignment)),
                float(int(opt.file_alignment)),
                float(int(opt.sizeof_image)),
                float(int(opt.sizeof_headers)),
                float(int(opt.checksum)),
                float(int(opt.subsystem)),
                float(int(opt.dll_characteristics)),
                float(int(opt.sizeof_stack_reserve)),
                float(int(opt.sizeof_stack_commit)),
                float(int(opt.sizeof_heap_reserve)),
                float(int(opt.sizeof_heap_commit)),
                float(int(opt.numberof_rva_and_size)),
            ])
        except Exception:
            features.extend([0.0] * 19)

        try:
            sections = binary.sections
            features.append(float(len(sections)))
            if sections:
                entropies = []
                sizes     = []
                for s in sections:
                    content = bytes(s.content)
                    if content:
                        bc = np.bincount(
                            np.frombuffer(
                                content,
                                dtype=np.uint8),
                            minlength=256)
                        p = bc / len(content)
                        e = -np.sum(
                            p * np.log2(p + 1e-10))
                        entropies.append(e)
                    else:
                        entropies.append(0.0)
                    sizes.append(
                        float(s.virtual_size))
                features.extend([
                    float(np.mean(entropies)),
                    float(np.min(entropies)),
                    float(np.max(entropies)),
                    float(np.mean(sizes)),
                ])
            else:
                features.extend([0.0] * 4)
        except Exception:
            features.extend([0.0] * 5)

        try:
            imports = list(binary.imports)
            features.append(float(len(imports)))
            total_funcs = sum(
                len(list(lib.entries))
                for lib in imports)
            features.append(float(total_funcs))
        except Exception:
            features.extend([0.0] * 2)

        try:
            exports = list(
                binary.exported_functions)
            features.append(float(len(exports)))
        except Exception:
            features.append(0.0)

        byte_hist = np.bincount(
            np.frombuffer(
                file_bytes[
                    :min(len(file_bytes), 4096)],
                dtype=np.uint8),
            minlength=256).astype(np.float32)
        byte_hist = byte_hist / (
            byte_hist.sum() + 1)
        features.extend(byte_hist.tolist())

        TARGET = 2381
        if len(features) < TARGET:
            features.extend(
                [0.0] * (TARGET - len(features)))
        features = features[:TARGET]

        raw      = np.array(
            features,
            dtype=np.float32).reshape(1, -1)
        scaled   = scaler_ember.transform(raw)
        selected = selector_ember.transform(scaled)
        return selected, None

    except Exception as e:
        return None, \
            f"Erreur extraction manuelle : {str(e)}"


def extract_static_features(file_bytes: bytes):
    """
    Point d'entrée — Approche sécuritaire.

    Utilise les DEUX pipelines (EMBER + manuel)
    et retourne les deux pour que predictor.py
    prenne le score MAX par modèle.

    En cybersécurité : un faux négatif (malware
    non détecté) est plus dangereux qu'un faux
    positif (fichier bénin bloqué).
    """
    feat_ember  = None
    feat_manual = None

    # Pipeline 1 — EMBER complet
    if EMBER_AVAILABLE:
        feat_ember, err = \
            extract_static_features_ember(file_bytes)
        if feat_ember is None:
            print(f"⚠️ EMBER échoué : {err}")

    # Pipeline 2 — Extraction manuelle
    feat_manual, err = \
        extract_static_features_manual(file_bytes)
    if feat_manual is None:
        print(f"⚠️ Manuel échoué : {err}")

    # Un seul disponible → retourner celui-là
    if feat_ember is not None and \
            feat_manual is None:
        return feat_ember, None
    if feat_manual is not None and \
            feat_ember is None:
        return feat_manual, None
    if feat_ember is None and \
            feat_manual is None:
        return None, "Aucun pipeline disponible"

    # Les deux disponibles → retourner dict
    return {
        'ember' : feat_ember,
        'manual': feat_manual
    }, None