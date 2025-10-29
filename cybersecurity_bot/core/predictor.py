import pandas as pd
import joblib
import os

MODEL_PATH = 'malware_model.pkl'

def predict_process_risk(features):
    """
    features: list of lists with shape (n_samples, n_features)
    Returns a risk score float from 0 to 1
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)
    columns = ['cpu_percent', 'memory_percent', 'num_threads', 'num_connections']
    
    X = pd.DataFrame(features, columns=columns)

    proba = model.predict_proba(X)

    if proba.shape[1] == 1:
        # Model learned only one class, return 0 or 1 accordingly
        # Assuming only class 0 present, so risk=0
        return 0.0
    else:
        # Return probability of class 1 (malicious)
        return float(proba[0][1])
