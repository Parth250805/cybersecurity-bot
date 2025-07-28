import hashlib
import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"

headers = {
    "x-apikey": API_KEY
}

def get_file_hash(file_path):
    """Calculate the SHA256 hash of the given file."""
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            return hashlib.sha256(file_data).hexdigest()
    except Exception as e:
        print(f"❌ Error hashing file: {e}")
        return None

def check_virustotal(file_hash):
    """Check the hash against VirusTotal API."""
    try:
        response = requests.get(VT_URL + file_hash, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if malicious_count > 0:
                return True, stats  # Malicious
            else:
                return False, stats  # Clean
        elif response.status_code == 404:
            return None, {}  # Not found in VirusTotal
        else:
            print(f"⚠️ VirusTotal API error: {response.status_code}")
            return None, {}
    except Exception as e:
        print(f"❌ Error calling VirusTotal: {e}")
        return None, {}
