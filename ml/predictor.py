import os
import joblib

from ml.feature_extractor import extract_features


MODEL_PATH = "ml/url_threat_model.joblib"


_model = None


def load_model():
    global _model

    if _model is None:

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


def predict_url(url):

    model = load_model()

    features = extract_features(url)

    prediction = model.predict([features])[0]

    probabilities = model.predict_proba([features])[0]

    confidence = max(probabilities) * 100

    if prediction == 1:
        classification = "MALICIOUS"
    else:
        classification = "BENIGN"

    return {
        "prediction": int(prediction),
        "classification": classification,
        "confidence": round(float(confidence), 2)
    }