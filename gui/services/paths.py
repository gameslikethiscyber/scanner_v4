"""
Path helpers — data files live outside the repository (user AppData dir).
"""

import os
import sys

APP_DIR_NAME = "SEACorporateScanner"


def project_root() -> str:
    """Absolute path of the repository root (parent of the ``gui`` package)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))


def data_dir() -> str:
    """Per-user writable directory for settings / history / logs."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(base, APP_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def settings_path() -> str:
    return os.path.join(data_dir(), "settings.json")


def history_path() -> str:
    return os.path.join(data_dir(), "history.json")


def default_reports_dir() -> str:
    return os.path.join(project_root(), "reports")
