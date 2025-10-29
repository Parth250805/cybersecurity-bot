import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
SRC_DIR = PROJECT_ROOT / "cybersecurity_bot"

FOLDER_MAP = {
    # core
    "detector": "core",
    "predictor": "core",
    "feature_collector": "core",
    "vt_scanner": "core",
    "generate_benign_data": "core",
    "generate_malicious_data": "core",
    "train_model": "core",
    "malware_model": "core",
    # gui
    "gui": "gui",
    "simple_gui": "gui",
    "debug_gui": "gui",
    "run_gui": "gui",
    "start_simple_gui": "gui",
    "create_icon": "gui",
    "icon": "gui",
    # utils
    "logger": "utils",
    "notifier": "utils",
    "emailer": "utils",
    "killer": "utils",
    "check_dataset": "utils",
    "append_test_row": "utils",
    "fix_header": "utils",
    "threats_export": "utils",
    # config
    "config": "config",
    # data
    "dataset": "data",
    "detection": "data",
}

SUBFOLDERS = ["core", "gui", "utils", "config", "data"]

def ensure_structure():
    SRC_DIR.mkdir(exist_ok=True)
    for sub in SUBFOLDERS:
        path = SRC_DIR / sub
        path.mkdir(parents=True, exist_ok=True)
        (path / "__init__.py").touch(exist_ok=True)
    (SRC_DIR / "__init__.py").touch(exist_ok=True)

def move_files():
    for file in PROJECT_ROOT.glob("*.*"):
        if file.name.startswith("restructure_project"):
            continue
        if file.suffix not in [".py", ".yml", ".csv", ".pkl", ".log", ".ico", ".bat"]:
            continue

        target_subfolder = None
        for key, sub in FOLDER_MAP.items():
            if key.lower() in file.stem.lower():
                target_subfolder = sub
                break

        if not target_subfolder:
            continue

        dest = SRC_DIR / target_subfolder / file.name
        dest.parent.mkdir(parents=True, exist_ok=True)

        if dest.exists():
            dest = dest.with_name(dest.stem + "_dup" + dest.suffix)

        shutil.move(str(file), str(dest))
        print(f"✅ Moved {file.name} → {target_subfolder}/")

def main():
    print("🔧 Finalizing Level-1 Restructure...")
    ensure_structure()
    move_files()
    print("✅ All files organized successfully!")

if __name__ == "__main__":
    main()
