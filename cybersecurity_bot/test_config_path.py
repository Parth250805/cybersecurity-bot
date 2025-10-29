from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent / "cybersecurity_bot" / "config" / "config.yaml"
print("Resolved path:", CONFIG_PATH)
print("Exists?", CONFIG_PATH.exists())

