"""Use the same implementation that registered this installation's hooks."""
import importlib
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
if (_root / "agentsfence").is_dir():
    _entry = _root / "__init__.py"
    _package = next((module.__name__ for module in tuple(sys.modules.values())
                     if module and getattr(module, "__file__", None)
                     and Path(module.__file__).resolve() == _entry), None)
    if _package is None:
        raise RuntimeError("Load the AgentsFence directory plugin before its dashboard API.")
    router = importlib.import_module(_package + ".agentsfence.desktop_api").router
else:
    from agentsfence.desktop_api import router

__all__ = ["router"]
