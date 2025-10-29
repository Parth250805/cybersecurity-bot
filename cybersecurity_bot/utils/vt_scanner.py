from pathlib import Path
import hashlib
import requests
import os
import time
import json
from collections import deque
from dotenv import load_dotenv
import yaml

# === Load .env and configuration ===
load_dotenv()

# Resolve config.yaml path automatically
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"

# === Default values in case config fails ===
DEFAULT_TTL_MINUTES = 60
DEFAULT_CACHE_PATH = "vt_cache.json"
DEFAULT_RATE_LIMIT = 10

# === VirusTotal API setup ===
API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"
headers = {"x-apikey": API_KEY or ""}


def _load_config():
    """Load VirusTotal-related settings from config.yaml (if available)."""
    cfg = {}
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"⚠️ Failed to load VT config: {e}")

    ttl_min = int(cfg.get("vt_cache_ttl_minutes", DEFAULT_TTL_MINUTES))
    cache_path = cfg.get("vt_cache_file", DEFAULT_CACHE_PATH)
    rate_per_min = int(cfg.get("vt_rate_limit_per_min", DEFAULT_RATE_LIMIT))
    return ttl_min, cache_path, rate_per_min


# === Global cache + rate limiting ===
_VT_TTL_MINUTES, _VT_CACHE_PATH, _VT_RATE_PER_MIN = _load_config()
_vt_cache = None
_vt_times = deque(maxlen=120)


def _load_cache():
    """Load VirusTotal cache from disk."""
    global _vt_cache
    if _vt_cache is not None:
        return _vt_cache
    try:
        if os.path.exists(_VT_CACHE_PATH):
            with open(_VT_CACHE_PATH, "r", encoding="utf-8") as f:
                _vt_cache = json.load(f)
        else:
            _vt_cache = {}
    except Exception:
        _vt_cache = {}
    return _vt_cache


def _save_cache():
    """Persist VirusTotal cache to disk."""
    try:
        with open(_VT_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_vt_cache or {}, f, indent=2)
    except Exception as e:
        print(f"⚠️ Failed to save VT cache: {e}")


def get_file_hash(file_path):
    """Calculate the SHA256 hash of a given file."""
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            return hashlib.sha256(file_data).hexdigest()
    except Exception as e:
        print(f"❌ Error hashing file {file_path}: {e}")
        return None


def check_virustotal(file_hash):
    """Check the hash against VirusTotal API with caching and rate limiting.

    Returns: (bool|None verdict, dict stats)
      True  -> malicious
      False -> clean
      None  -> unknown/error
    """
    if not file_hash:
        return None, {}

    cache = _load_cache()
    now = time.time()

    # Check cached result
    entry = cache.get(file_hash)
    if entry and (now - entry.get("ts", 0) <= _VT_TTL_MINUTES * 60):
        verdict = entry.get("verdict")
        stats = entry.get("stats", {})
        return verdict, stats

    # Enforce rate limit
    while _vt_times and now - _vt_times[0] > 60:
        _vt_times.popleft()
    if len(_vt_times) >= _VT_RATE_PER_MIN:
        print("⚠️ VirusTotal rate limit reached, skipping check.")
        return None, {}

    # Query VirusTotal
    try:
        _vt_times.append(now)
        response = requests.get(VT_URL + file_hash, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            verdict = True if malicious_count > 0 else False
            cache[file_hash] = {"verdict": verdict, "stats": stats, "ts": now}
            _save_cache()
            return verdict, stats

        elif response.status_code == 404:
            cache[file_hash] = {"verdict": None, "stats": {}, "ts": now}
            _save_cache()
            return None, {}

        else:
            print(f"⚠️ VirusTotal API returned {response.status_code}")
            return None, {}

    except Exception as e:
        print(f"❌ VirusTotal query failed: {e}")
        return None, {}
