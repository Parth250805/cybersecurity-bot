# predictor.py

import joblib
import os

MODEL_PATH = 'malware_model.pkl'

def predict_process_risk(features):
    """
    features: list of lists, e.g. [[cpu, memory, threads, connections]]
    Returns: probability/risk score for each feature row.
    """
    if not os.path.exists(MODEL_PATH):
        raise ValueError("Model file not found: malware_model.pkl")
    model = joblib.load(MODEL_PATH)
    result = model.predict_proba(features)
    # Assuming the malicious class is 1 (second column)
    return result[0][1]
