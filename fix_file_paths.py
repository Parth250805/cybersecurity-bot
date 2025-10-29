import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
PACKAGE_NAME = "cybersecurity_bot"
EXTENSIONS = (".yaml", ".yml", ".csv", ".pkl", ".log", ".txt", ".ico")

OPEN_PATTERN = re.compile(r'open\s*\(\s*["\']([^"\']+\.(?:yaml|yml|csv|pkl|log|txt|ico))["\']')

def safe_read_text(file_path: Path):
    """Try UTF-8 first, then fallback to cp1252 or latin-1."""
    encodings = ["utf-8", "cp1252", "latin-1"]
    for enc in encodings:
        try:
            return file_path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError(f"Unable to decode {file_path} with {encodings}")

def fix_file_paths(py_file: Path):
    try:
        text = safe_read_text(py_file)
    except Exception as e:
        print(f"⚠️ Skipped non-readable file: {py_file.name} ({e})")
        return

    backup_path = py_file.with_suffix(py_file.suffix + ".bak")
    backup_path.write_text(text, encoding="utf-8")

    modified = False
    new_lines = []
    has_path_import = "from pathlib import Path" in text

    for line in text.splitlines():
        match = OPEN_PATTERN.search(line)
        if match:
            file_name = match.group(1)
            corrected = (
                f'CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "{file_name}"'
                if "config" in file_name.lower()
                else f'FILE_PATH = Path(__file__).resolve().parents[1] / "{file_name}"'
            )
            replacement = f'open({ "CONFIG_PATH" if "config" in file_name.lower() else "FILE_PATH" }, "r")'
            line = OPEN_PATTERN.sub(replacement, line)
            new_lines.insert(0, corrected)
            modified = True

        new_lines.append(line)

    if modified:
        if not has_path_import:
            new_lines.insert(0, "from pathlib import Path\n")
        py_file.write_text("\n".join(new_lines), encoding="utf-8")
        print(f"✅ Fixed paths in: {py_file.relative_to(PROJECT_ROOT)}")

def main():
    print("🔧 Continuing global file-path correction...\n")
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if py_file.name in ["fix_file_paths.py", "fix_import_paths.py", "restructure_project.py"]:
            continue
        fix_file_paths(py_file)
    print("\n✅ File-path correction complete!")

if __name__ == "__main__":
    main()

