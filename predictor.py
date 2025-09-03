# predictor.py

import joblib
import os
import pandas as pd

MODEL_PATH = 'malware_model.pkl'

def predict_process_risk(features):
    """Return model probability for the malicious class.

    Accepts either a list-of-lists [[cpu, memory, threads, connections]] or a
    pandas.DataFrame with the expected feature names. We convert to a DataFrame
    with column names so scikit-learn does not warn about missing feature names.
    """
    if not os.path.exists(MODEL_PATH):
        raise ValueError("Model file not found: malware_model.pkl")
    model = joblib.load(MODEL_PATH)
    if not isinstance(features, pd.DataFrame):
        features = pd.DataFrame(features, columns=[
            'cpu_percent', 'memory_percent', 'num_threads', 'num_connections'
        ])
    result = model.predict_proba(features)
    # Assuming the malicious class is 1 (second column)
    return result[0][1]
