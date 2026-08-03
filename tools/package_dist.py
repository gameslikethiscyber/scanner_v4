"""
Assemble the SEA Scanner Pro v5.0.0 distribution tree and produce the
deliverable ZIPs (source + full distribution) for CodeCanyon / Gumroad.

Usage:
    python tools/package_dist.py
"""
import os
import shutil
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = "5.0.0"
PRODUCT = "SEA Scanner Pro"
ROOT_NAME = f"{PRODUCT} v{VERSION}"

STAGE = os.path.join(REPO, "dist_stage")
OUT = os.path.join(REPO, "dist", "packages")
os.makedirs(OUT, exist_ok=True)

# Top-level dirs that are OTHER products (web UI) or build artifacts.
EXCLUDE_DIRS = {
    "backend", "frontend", "node_modules", "__pycache__",
    "dist", "build", "dist_stage", ".git", "logs", "reports",
    "venv", ".venv", ".idea", "docs",
}
EXCLUDE_FILES = {"audit_compare.py", "audit_full.py"}


def wipe(path):
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def copy_tree(src, dst, exclude_dirs=None, exclude_files=None):
    exclude_dirs = exclude_dirs or set()
    exclude_files = exclude_files or set()
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        rel = os.path.relpath(root, src)
        target = os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for f in files:
            if f in exclude_files or f.endswith((".pyc", ".pyo")):
                continue
            shutil.copy2(os.path.join(root, f), os.path.join(target, f))


def make_zip(src_dir, zip_path, top_name):
    wipe(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(src_dir):
            for f in files:
                full = os.path.join(root, f)
                arcrel = os.path.relpath(full, src_dir)
                arc = os.path.join(top_name, arcrel).replace("\\", "/")
                z.write(full, arc)
    print("zip:", zip_path)


def main():
    wipe(STAGE)
    root = os.path.join(STAGE, ROOT_NAME)

    # ---- Source ---------------------------------------------------------
    src = os.path.join(root, "Source")
    os.makedirs(src, exist_ok=True)
    for item in os.listdir(REPO):
        p = os.path.join(REPO, item)
        if os.path.isdir(p):
            if item in {"core", "scanners", "gui", "templates", "payloads",
                        "tests", "benchmarks", "docs", "project_docs", "tools"}:
                wipe(os.path.join(src, item))
                shutil.copytree(p, os.path.join(src, item),
                                ignore=shutil.ignore_patterns(
                                    "__pycache__", "*.pyc"))
        elif os.path.isfile(p):
            if item in EXCLUDE_FILES or item.endswith(".pyc"):
                continue
            shutil.copy2(p, os.path.join(src, item))

    # Installation guide for the source package
    shutil.copy2(os.path.join(REPO, "dist_assets", "INSTALL_SOURCE.md"),
                 os.path.join(src, "INSTALL.md"))

    # ---- Windows --------------------------------------------------------
    win = os.path.join(root, "Windows")
    built = os.path.join(REPO, "dist", "Sea Scanner Pro")
    if os.path.isdir(built):
        shutil.copytree(built, os.path.join(win, "Sea Scanner Pro"))  # exe + _internal
        readme = os.path.join(REPO, "dist_assets", "windows_README.txt")
        if os.path.exists(readme):
            shutil.copy2(readme, os.path.join(win, "README.txt"))

    # ---- Documentation --------------------------------------------------
    doc_dir = os.path.join(root, "Documentation")
    os.makedirs(doc_dir, exist_ok=True)
    for f in ("README.md",):
        sp = os.path.join(REPO, f)
        if os.path.exists(sp):
            shutil.copy2(sp, os.path.join(doc_dir, f))
    for d, sub in [("docs", ""), ("project_docs", "")]:
        base = os.path.join(REPO, d)
        for f in sorted(os.listdir(base)):
            shutil.copy2(os.path.join(base, f), os.path.join(doc_dir, f))

    # ---- Examples -------------------------------------------------------
    ex = os.path.join(root, "Examples")
    os.makedirs(ex, exist_ok=True)
    for f in ["report_20260802_022010.html", "report_20260802_161939.html"]:
        sp = os.path.join(REPO, "reports", f)
        if os.path.exists(sp):
            shutil.copy2(sp, os.path.join(ex, f))

    # ---- License at root ------------------------------------------------
    shutil.copy2(os.path.join(REPO, "LICENSE"), os.path.join(root, "LICENSE"))

    # ---- Zip (source-only + full) ----------------------------------------
    make_zip(root, os.path.join(OUT, f"SEA_Scanner_Pro_v{VERSION}_FULL.zip"), ROOT_NAME)

    # Source-only zip
    wip = os.path.join(STAGE, "src_only")
    wipe(wip)
    shutil.copytree(os.path.join(root, "Source"), os.path.join(wip, "Source"))
    shutil.copy2(os.path.join(REPO, "LICENSE"), os.path.join(wip, "LICENSE"))
    make_zip(wip, os.path.join(OUT, f"SEA_Scanner_Pro_v{VERSION}_SOURCE.zip"), ROOT_NAME)

    print("done")


if __name__ == "__main__":
    main()