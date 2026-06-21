"""
safe-pip — Python package security scanner.
Scans PyPI packages for security risks before installation.
"""

__version__ = "1.1.0"
__author__  = "safe-pip contributors"
__license__ = "MIT"


def _check_deps() -> None:
    """Check required third-party dependencies are installed."""
    _REQUIRED = {
        "requests":  "pip install requests",
        "rich":      "pip install rich",
        "click":     "pip install click",
    }
    missing = []
    for mod, fix in _REQUIRED.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append((mod, fix))

    if missing:
        import sys
        print("safe-pip: missing required dependencies\n", file=sys.stderr)
        for mod, fix in missing:
            print(f"  ✗  {mod:<12}  →  run: {fix}", file=sys.stderr)
        sys.exit(1)


_check_deps()
