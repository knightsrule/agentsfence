"""Directory entry point: always run this checkout's implementation, failing closed."""

import importlib
import importlib.util
import sys
from pathlib import Path

_impl = Path(__file__).resolve().parent / "agentsfence"
# A desktop launched from the repository's parent may import this outer
# directory as `agentsfence`. Load the real package under its canonical name.
if __name__ == "agentsfence":
    _spec = importlib.util.spec_from_file_location("agentsfence", _impl / "__init__.py", submodule_search_locations=[str(_impl)])
    if _spec is None or _spec.loader is None:
        raise ImportError("Cannot locate the AgentsFence implementation")
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["agentsfence"] = _module
    _spec.loader.exec_module(_module)

    from agentsfence.plugin import register
else:
    # Hermes supplies a package namespace for each directory plugin. Preserve
    # it so the checkout and an installed wheel can coexist without mixed code.
    _package = __name__

    def _failsafe():  # type: ignore[no-untyped-def]
        """The standard-library failsafe, loaded by path: it must work when the package cannot import."""
        spec = importlib.util.spec_from_file_location(f"{_package}._agentsfence_failsafe", _impl / "failsafe.py")
        if spec is None or spec.loader is None:
            raise ImportError("Cannot locate the AgentsFence failsafe")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def register(ctx):  # type: ignore[no-untyped-def]
        """Run this checkout's register(ctx); on any failure, block every tool call."""
        _failsafe().guarded_register(ctx, lambda: importlib.import_module(_package + ".agentsfence.plugin"))

__all__ = ["register"]
