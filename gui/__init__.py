"""
SEA Corporate Security Scanner — Desktop GUI (PySide6).

Layered architecture: the ``gui`` package is the presentation layer and depends
on the existing ``core`` + ``scanners`` packages (business logic). The engine
never imports from ``gui``.
"""

from gui.version import APP_NAME, ENGINE_VERSION, ORGANIZATION

__version__ = "2.0.0"
GUI_VERSION = __version__

__all__ = ["APP_NAME", "ENGINE_VERSION", "GUI_VERSION", "ORGANIZATION", "__version__"]
