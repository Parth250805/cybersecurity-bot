import re
from pathlib import Path

# Root of your repo
PROJECT_ROOT = Path(__file__).parent.resolve()
PACKAGE_NAME = "cybersecurity_bot"

# Folder mapping to know where each module lives
MODULE_MAP = {
    "core": ["detector", "predictor", "feature_collector", "vt_scanner",
             "generate_benign_data", "generate_malicious_data", "train_model", "malware_model"],
    "gui": ["gui", "simple_gui", "debug_gui", "run_gui", "start_simple_gui", "create_icon"],
    "utils": ["logger", "notifier", "emailer", "killer", "check_dataset",
              "append_test_row", "fix_header", "threats_export"],
    "config": ["config"],
    "data": ["dataset", "detection"]
}

# Build reverse lookup
MODULE_LOOKUP = {name: group for group, names in MODULE_MAP.items() for name in names}

def find_target_module(name):
    """Return full import path for a given module name."""
    for key in MODULE_LOOKUP:
        if key.lower() in name.lower():
            return f"{PACKAGE_NAME}.{MODULE_LOOKUP[key]}.{key}"
    return None

def fix_imports_in_file(file_path: Path):
    text = file_path.read_text(encoding="utf-8")

    # Make a backup first
    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
    backup_path.write_text(text, encoding="utf-8")

    new_lines = []
    modified = False

    for line in text.splitlines():
        # Match "from X import Y" and "import X"
        match_from = re.match(r'^\s*from\s+([\w_]+)\s+import', line)
        match_import = re.match(r'^\s*import\s+([\w_]+)', line)

        if match_from:
            mod = match_from.group(1)
            target = find_target_module(mod)
            if target:
                new_line = line.replace(f"from {mod}", f"from {target}")
                new_lines.append(new_line)
                modified = True
                continue

        elif match_import:
            mod = match_import.group(1)
            target = find_target_module(mod)
            if target:
                new_line = line.replace(f"import {mod}", f"from {target} import *")
                new_lines.append(new_line)
                modified = True
                continue

        new_lines.append(line)

    if modified:
        file_path.write_text("\n".join(new_lines), encoding="utf-8")
        print(f"✅ Fixed imports in: {file_path.relative_to(PROJECT_ROOT)}")

def main():
    print("🔧 Starting Level 2: Auto Import Path Correction...\n")
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if py_file.name in ["fix_import_paths.py", "restructure_project.py"]:
            continue
        fix_imports_in_file(py_file)
    print("\n✅ Import path correction complete!")

if __name__ == "__main__":
    main()
