# ============================================================
# predictor.py — Weighted Vote double pipeline sécuritaire
# ============================================================
import os
import numpy as np
import joblib
import shap
import tensorflow as tf
from tensorflow import keras
from config import (MODEL_DIR, THRESHOLDS,
                    WEIGHTS_EMBER, WEIGHTS_MALMEM)
import warnings
warnings.filterwarnings('ignore')

# ── Classes custom FT-Transformer ─────────────────────────
class FeatureTokenizer(keras.layers.Layer):
    def __init__(self, n_features, d_token, **kwargs):
        super().__init__(**kwargs)
        self.n_features = n_features
        self.d_token    = d_token
    def build(self, input_shape):
        self.W = self.add_weight(
            shape=(self.n_features, self.d_token),
            initializer='glorot_uniform', trainable=True)
        self.b = self.add_weight(
            shape=(self.n_features, self.d_token),
            initializer='zeros', trainable=True)
        super().build(input_shape)
    def call(self, x):
        return (x[:, :, None] * self.W[None, :, :] +
                self.b[None, :, :])
    def get_config(self):
        config = super().get_config()
        config.update({'n_features': self.n_features,
                       'd_token'   : self.d_token})
        return config

class ClsToken(keras.layers.Layer):
    def __init__(self, d_token, **kwargs):
        super().__init__(**kwargs)
        self.d_token = d_token
    def build(self, input_shape):
        self.cls = self.add_weight(
            shape=(1, 1, self.d_token),
            initializer='zeros', trainable=True)
        super().build(input_shape)
    def call(self, x):
        batch_size = tf.shape(x)[0]
        cls_tokens = tf.repeat(
            self.cls, batch_size, axis=0)
        return tf.concat([cls_tokens, x], axis=1)
    def get_config(self):
        config = super().get_config()
        config.update({'d_token': self.d_token})
        return config

class TransformerBlock(keras.layers.Layer):
    def __init__(self, d_token, n_heads,
                 ffn_factor=2.0,
                 dropout_rate=0.1, **kwargs):
        super().__init__(**kwargs)
        self.d_token      = d_token
        self.n_heads      = n_heads
        self.ffn_factor   = ffn_factor
        self.dropout_rate = dropout_rate
    def build(self, input_shape):
        self.attention = \
            keras.layers.MultiHeadAttention(
                num_heads=self.n_heads,
                key_dim=self.d_token // self.n_heads,
                dropout=self.dropout_rate)
        self.ffn = keras.Sequential([
            keras.layers.Dense(
                int(self.d_token * self.ffn_factor),
                activation='relu'),
            keras.layers.Dropout(self.dropout_rate),
            keras.layers.Dense(self.d_token)])
        self.norm1 = keras.layers.LayerNormalization(
            epsilon=1e-6)
        self.norm2 = keras.layers.LayerNormalization(
            epsilon=1e-6)
        self.drop1 = keras.layers.Dropout(
            self.dropout_rate)
        self.drop2 = keras.layers.Dropout(
            self.dropout_rate)
        super().build(input_shape)
    def call(self, x, training=False):
        attn = self.attention(
            self.norm1(x), self.norm1(x),
            training=training)
        x = x + self.drop1(attn, training=training)
        ffn = self.ffn(
            self.norm2(x), training=training)
        return x + self.drop2(ffn, training=training)
    def get_config(self):
        config = super().get_config()
        config.update({
            'd_token'     : self.d_token,
            'n_heads'     : self.n_heads,
            'ffn_factor'  : self.ffn_factor,
            'dropout_rate': self.dropout_rate})
        return config

CUSTOM_OBJECTS = {
    'FeatureTokenizer': FeatureTokenizer,
    'ClsToken'        : ClsToken,
    'TransformerBlock': TransformerBlock
}

# ── Chargement des modèles ─────────────────────────────────
print("Chargement des modèles...")

rf_malmem  = joblib.load(os.path.join(
    MODEL_DIR, "rf_malmem.pkl"))
rf_ember   = joblib.load(os.path.join(
    MODEL_DIR, "rf_ember.pkl"))
xgb_malmem = joblib.load(os.path.join(
    MODEL_DIR, "xgb_malmem.pkl"))
xgb_ember  = joblib.load(os.path.join(
    MODEL_DIR, "xgb_ember.pkl"))
lgb_malmem = joblib.load(os.path.join(
    MODEL_DIR, "lgb_malmem.pkl"))
lgb_ember  = joblib.load(os.path.join(
    MODEL_DIR, "lgb_ember.pkl"))

cnn_malmem = keras.models.load_model(
    os.path.join(MODEL_DIR, "cnn1d_malmem.keras"))
cnn_ember  = keras.models.load_model(
    os.path.join(MODEL_DIR, "cnn1d_ember.keras"))
ft_malmem  = keras.models.load_model(
    os.path.join(MODEL_DIR,
                 "ft_transformer_malmem.keras"),
    custom_objects=CUSTOM_OBJECTS)
ft_ember   = keras.models.load_model(
    os.path.join(MODEL_DIR,
                 "ft_transformer_ember.keras"),
    custom_objects=CUSTOM_OBJECTS)

print("✅ Tous les modèles chargés")


def _predict_single_model(model, features, features_alt,
                           name, threshold, weight,
                           use_proba):
    """
    Prédit avec un modèle sur les features principales.
    Si features_alt (pipeline alternatif) est disponible,
    prend le MAX des deux scores → approche sécuritaire.
    """
    # Score pipeline principal
    if use_proba:
        proba = float(
            model.predict_proba(features)[:, 1][0])
    else:
        x = (features.reshape(-1, features.shape[1], 1)
             if name == 'CNN1D' else features)
        proba = float(
            model.predict(x, verbose=0).flatten()[0])

    # Score pipeline alternatif si disponible
    if features_alt is not None:
        if use_proba:
            proba_alt = float(
                model.predict_proba(
                    features_alt)[:, 1][0])
        else:
            x_alt = (features_alt.reshape(
                -1, features_alt.shape[1], 1)
                if name == 'CNN1D' else features_alt)
            proba_alt = float(
                model.predict(
                    x_alt, verbose=0).flatten()[0])

        # MAX → approche sécuritaire
        proba = max(proba, proba_alt)

    vote = int(proba >= threshold)
    return proba, vote


def predict_weighted_vote(features_ember,
                           features_malmem=None):
    """
    Weighted Vote avec double pipeline sécuritaire.

    Si features_ember est un dict {'ember', 'manual'},
    chaque modèle prédit sur les deux et prend le MAX.

    En cybersécurité : mieux vaut un faux positif
    qu'un faux négatif (malware non détecté).
    """
    votes_all   = []
    probas_all  = []
    model_names = []
    weights_all = []

    # ── Déterminer les features statiques ──────────────
    if isinstance(features_ember, dict):
        feat_main = features_ember.get('ember')
        feat_alt  = features_ember.get('manual')
        # Si ember échoué → utiliser manuel comme main
        if feat_main is None:
            feat_main = feat_alt
            feat_alt  = None
    else:
        feat_main = features_ember
        feat_alt  = None

    # ── Prédictions EMBER (statique) ──────────────────
    if feat_main is not None:
        models_ember = [
            (rf_ember,  'RF',
             THRESHOLDS['RF_ember'],
             WEIGHTS_EMBER['RF'],       True),
            (xgb_ember, 'XGBoost',
             THRESHOLDS['XGB_ember'],
             WEIGHTS_EMBER['XGBoost'],  True),
            (lgb_ember, 'LightGBM',
             THRESHOLDS['LGB_ember'],
             WEIGHTS_EMBER['LGB'],      True),
            (cnn_ember, 'CNN1D',
             THRESHOLDS['CNN_ember'],
             WEIGHTS_EMBER['CNN1D'],    False),
            (ft_ember,  'FT-Transf',
             THRESHOLDS['FT_ember'],
             WEIGHTS_EMBER['FT'],       False),
        ]

        for model, name, thresh, weight, use_proba \
                in models_ember:
            proba, vote = _predict_single_model(
                model, feat_main, feat_alt,
                name, thresh, weight, use_proba)

            votes_all.append(vote)
            probas_all.append(proba)
            model_names.append(
                f"{name} (statique)")
            weights_all.append(weight)

    # ── Prédictions CIC-MalMem (dynamique) ────────────
    if features_malmem is not None:
        models_malmem = [
            (rf_malmem,  'RF',
             THRESHOLDS['RF_malmem'],
             WEIGHTS_MALMEM['RF'],       True),
            (xgb_malmem, 'XGBoost',
             THRESHOLDS['XGB_malmem'],
             WEIGHTS_MALMEM['XGBoost'],  True),
            (lgb_malmem, 'LightGBM',
             THRESHOLDS['LGB_malmem'],
             WEIGHTS_MALMEM['LGB'],      True),
            (cnn_malmem, 'CNN1D',
             THRESHOLDS['CNN_malmem'],
             WEIGHTS_MALMEM['CNN1D'],    False),
            (ft_malmem,  'FT-Transf',
             THRESHOLDS['FT_malmem'],
             WEIGHTS_MALMEM['FT'],       False),
        ]

        for model, name, thresh, weight, use_proba \
                in models_malmem:
            fm    = features_malmem
            proba, vote = _predict_single_model(
                model, fm, None,
                name, thresh, weight, use_proba)

            votes_all.append(vote)
            probas_all.append(proba)
            model_names.append(
                f"{name} (dynamique)")
            weights_all.append(weight)

    # ── Weighted Vote final ───────────────────────────
    if not votes_all:
        return None

    weights_arr  = np.array(weights_all)
    weights_norm = weights_arr / weights_arr.sum()
    confidence   = float(np.average(
        probas_all, weights=weights_norm))
    verdict      = "MALWARE" if confidence >= 0.5 \
                   else "BENIN"

    return {
        "verdict"        : verdict,
        "confidence"     : round(
            float(confidence) * 100, 2),
        "is_malware"     : verdict == "MALWARE",
        "votes"          : [
            {
                "model" : name,
                "vote"  : "Malware" if v == 1
                          else "Bénin",
                "proba" : round(
                    float(p) * 100, 2),
                "weight": round(float(w), 4)
            }
            for name, v, p, w in zip(
                model_names, votes_all,
                probas_all, weights_all)
        ],
        "n_models"       : int(len(votes_all)),
        "n_malware_votes": int(sum(votes_all))
    }


def compute_shap_values(features_ember):
    """Calcule les valeurs SHAP pour XGBoost EMBER."""
    try:
        # Extraire les features si dict
        if isinstance(features_ember, dict):
            fe = features_ember.get(
                'ember', features_ember.get('manual'))
        else:
            fe = features_ember

        if fe is None:
            return None

        explainer   = shap.TreeExplainer(xgb_ember)
        shap_values = explainer.shap_values(fe)
        importance  = np.abs(shap_values[0])
        top5_idx    = np.argsort(
            importance)[-5:][::-1]

        return {
            "indices"      : top5_idx.tolist(),
            "values"       : [
                round(float(importance[i]), 4)
                for i in top5_idx],
            "feature_names": [
                f"Feature_{i}" for i in top5_idx]
        }
    except Exception as e:
        print(f"⚠️ SHAP échoué : {e}")
        return None