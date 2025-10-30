import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
from pathlib import Path

def generate_sample_data(n_samples=1000):
    """
    Generate synthetic data for training:
    - Benign processes tend to have lower resource usage
    - Malicious processes tend to have higher resource usage and more connections
    """
    # Generate benign process data
    benign_cpu = np.random.normal(20, 15, (n_samples // 2, 1))  # Mean 20%, std 15%
    benign_cpu = np.clip(benign_cpu, 0, 100)
    benign_mem = np.random.normal(15, 10, (n_samples // 2, 1))  # Mean 15%, std 10%
    benign_mem = np.clip(benign_mem, 0, 100)
    benign_threads = np.random.normal(5, 3, (n_samples // 2, 1))  # Mean 5 threads
    benign_threads = np.clip(benign_threads, 1, 50)
    benign_connections = np.random.poisson(2, (n_samples // 2, 1))  # Mean 2 connections
    
    # Generate malicious process data
    malicious_cpu = np.random.normal(60, 20, (n_samples // 2, 1))  # Mean 60%, std 20%
    malicious_cpu = np.clip(malicious_cpu, 0, 100)
    malicious_mem = np.random.normal(45, 20, (n_samples // 2, 1))  # Mean 45%, std 20%
    malicious_mem = np.clip(malicious_mem, 0, 100)
    malicious_threads = np.random.normal(15, 8, (n_samples // 2, 1))  # Mean 15 threads
    malicious_threads = np.clip(malicious_threads, 1, 100)
    malicious_connections = np.random.poisson(8, (n_samples // 2, 1))  # Mean 8 connections
    
    # Combine features
    benign_data = np.hstack([benign_cpu, benign_mem, benign_threads, benign_connections])
    malicious_data = np.hstack([malicious_cpu, malicious_mem, malicious_threads, malicious_connections])
    
    # Create labels (0 for benign, 1 for malicious)
    benign_labels = np.zeros(n_samples // 2)
    malicious_labels = np.ones(n_samples // 2)
    
    # Combine all data
    X = np.vstack([benign_data, malicious_data])
    y = np.hstack([benign_labels, malicious_labels])
    
    # Create DataFrame
    df = pd.DataFrame(X, columns=['cpu_percent', 'memory_percent', 'num_threads', 'num_connections'])
    df['is_suspicious'] = y
    
    return df

try:
    # Try to load the dataset
    print("🔍 Looking for dataset.csv...")
    dataset_path = Path(__file__).resolve().parents[1] / 'data' / 'dataset.csv'
    df = pd.read_csv(dataset_path)
    print("✅ Found existing dataset")
except FileNotFoundError:
    print("⚠️ No dataset found, generating synthetic data...")
    df = generate_sample_data()
    print("✅ Generated synthetic training data")

# Features and labels
X = df[['cpu_percent', 'memory_percent', 'num_threads', 'num_connections']]
y = df['is_suspicious']

# Split into training and testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("📊 Classification Report:")
print(classification_report(y_test, y_pred))

# Save model
model_path = Path(__file__).resolve().parent / 'malware_model.pkl'
joblib.dump(model, model_path)
print(f"✅ Model saved as {model_path}")

# Test the model
print("\n🧪 Testing model with sample processes:")
test_cases = [
    [10, 5, 3, 1],   # Likely benign
    [80, 60, 20, 10] # Likely malicious
]
for case in test_cases:
    risk = model.predict_proba([case])[0][1]
    print(f"Process with CPU={case[0]}%, MEM={case[1]}%, "
          f"Threads={case[2]}, Connections={case[3]}")
    print(f"Risk Score: {risk:.3f}\n")
