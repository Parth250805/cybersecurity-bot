import re
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
PACKAGE_NAME = "cybersecurity_bot"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"

def extract_imports_from_file(py_file: Path):
    """Extract all imported module names from a file."""
    imports = set()
    with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = re.match(r"^\s*(?:from|import)\s+([a-zA-Z0-9_\.]+)", line)
            if match:
                pkg = match.group(1).split(".")[0]
                # Ignore built-ins and project-local modules
                if pkg not in ("cybersecurity_bot", "os", "sys", "re", "json", "time",
                               "pathlib", "shutil", "typing", "logging", "subprocess", "datetime"):
                    imports.add(pkg)
    return imports

def build_requirements():
    print("🔍 Scanning project for dependencies...")
    all_imports = set()
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if py_file.name in ["cleanup_project.py", "fix_file_paths.py", "fix_import_paths.py", "restructure_project.py"]:
            continue
        all_imports |= extract_imports_from_file(py_file)

    print(f"✅ Found {len(all_imports)} external imports: {', '.join(sorted(all_imports))}")

    with open(REQUIREMENTS_FILE, "w", encoding="utf-8") as f:
        for pkg in sorted(all_imports):
            f.write(pkg + "\n")

    print(f"📦 Generated new {REQUIREMENTS_FILE.name}")

def cleanup_imports():
    """Remove unused imports using autoflake."""
    print("\n🧽 Cleaning up unused imports...")
    try:
        subprocess.run(["autoflake", "--in-place", "--remove-all-unused-imports", "--recursive", str(PROJECT_ROOT)], check=True)
        print("✅ Unused imports cleaned.")
    except FileNotFoundError:
        print("⚠️ 'autoflake' not found. Installing...")
        subprocess.run(["pip", "install", "autoflake"])
        subprocess.run(["autoflake", "--in-place", "--remove-all-unused-imports", "--recursive", str(PROJECT_ROOT)])

def format_code():
    """Format code using black."""
    print("\n🎨 Formatting code with black...")
    try:
        subprocess.run(["black", str(PROJECT_ROOT)], check=True)
        print("✅ Code formatted successfully.")
    except FileNotFoundError:
        print("⚠️ 'black' not found. Installing...")
        subprocess.run(["pip", "install", "black"])
        subprocess.run(["black", str(PROJECT_ROOT)])

def main():
    print("🚀 Starting Level 3: Dependency & Code Cleanup...\n")
    build_requirements()
    cleanup_imports()
    format_code()
    print("\n🏁 Level 3 complete — project is clean and production-ready!")

if __name__ == "__main__":
    main()
