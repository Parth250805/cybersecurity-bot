import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load the dataset
df = pd.read_csv('dataset.csv')

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
joblib.dump(model, 'malware_model.pkl')
print("✅ Model saved as malware_model.pkl")
