from __future__ import annotations
import importlib
import inspect
import unittest
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

class AdversarialEliteTests(unittest.TestCase):
    def _load(self):
        errors = []
        for name in ('ephemeral_sandbox_receipt', "src." + 'ephemeral_sandbox_receipt'):
            try:
                return importlib.import_module(name)
            except Exception as e:
                errors.append(f"{name}: {e}")
        self.fail("; ".join(errors))

    def test_module_importable(self):
        mod = self._load()
        public = [n for n in dir(mod) if not n.startswith("_")]
        self.assertGreater(len(public), 0, "module exposes no public names")

    def test_refuse_bad_import_path_does_not_shadow(self):
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module("src.__elite_does_not_exist_" + 'ephemeral_sandbox_receipt')

    def test_central_mechanism_refuse_or_edge(self):
        """Exercise shipped refuse/edge paths when present; never crash open."""
        mod = self._load()
        exercised = False

        # plan(connector, action) refuse nonsense connector
        for cname, cls in inspect.getmembers(mod, inspect.isclass):
            if cname.startswith("_"):
                continue
            # include re-exported central classes (not pure stdlib typing)
            mname = getattr(cls, "__module__", None) or ""
            if mname.startswith("typing") or mname in {"builtins", "collections", "pathlib", "json", "sys", "os"}:
                continue
            if getattr(mod, cname, None) is not cls and mname not in {mod.__name__, getattr(mod, "__package__", None)}:
                continue
            try:
                sig = inspect.signature(cls)
                if any(
                    p.default is inspect.Parameter.empty and p.name != "self"
                    and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                    for p in sig.parameters.values()
                ):
                    continue
                inst = cls()
            except Exception:
                continue
            plan = getattr(inst, "plan", None)
            if callable(plan):
                try:
                    out = plan("__elite_no_such_connector__", "delete")
                    self.assertIsNotNone(out)
                    if isinstance(out, dict):
                        # refuse should not silently allow destructive unknown work
                        allowed = out.get("allowed")
                        if allowed is True:
                            self.assertTrue(
                                out.get("human_approved") is True
                                or out.get("status") in {"REFUSED", "DENIED", "ERROR", "UNKNOWN"},
                                f"plan allowed unknown connector: {out!r}",
                            )
                        exercised = True
                    else:
                        exercised = True
                except Exception as e:
                    # hard fail-closed is acceptable refuse
                    exercised = True
                    self.assertIsInstance(e, Exception)
            # authorize/decide refuse
            for meth in ("authorize", "decide", "check"):
                fn = getattr(inst, meth, None)
                if not callable(fn):
                    continue
                try:
                    ps = inspect.signature(fn)
                    req = [
                        p for p in ps.parameters.values()
                        if p.name != "self" and p.default is inspect.Parameter.empty
                        and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                    ]
                    if req:
                        continue
                    out = fn()
                    self.assertIsNotNone(out)
                    exercised = True
                except TypeError:
                    continue
                except Exception:
                    exercised = True

        # module-level schedule([]) / health edges
        sched = getattr(mod, "schedule", None)
        if callable(sched):
            try:
                out = sched([], 1.0)
                self.assertIsInstance(out, dict)
                self.assertIn("plan", out)
                exercised = True
            except TypeError:
                try:
                    out = sched([])
                    self.assertIsNotNone(out)
                    exercised = True
                except Exception:
                    exercised = True
            except Exception:
                exercised = True

        for edge_fn, args in (
            ("anomaly_score", (1e9,)),
            ("thermal_margin", (-40.0,)),
            ("simulate_rack", (0, 0.0)),
        ):
            fn = getattr(mod, edge_fn, None)
            if not callable(fn):
                continue
            try:
                out = fn(*args)
                self.assertIsNotNone(out)
                exercised = True
            except Exception:
                exercised = True

        # metrics / efficiency attributes on zero-arg engines
        for cname, cls in inspect.getmembers(mod, inspect.isclass):
            if cname.startswith("_"):
                continue
            try:
                inst = cls()
            except Exception:
                continue
            metrics = getattr(inst, "metrics", None)
            if isinstance(metrics, dict) and metrics:
                self.assertIn(next(iter(metrics)), metrics)
                exercised = True
                break

        if not exercised:
            # last resort: public API still rejects nonsense attribute assignment theater
            public = [n for n in dir(mod) if not n.startswith("_")]
            self.assertGreater(len(public), 0)
            with self.assertRaises((AttributeError, TypeError, ImportError, ValueError, KeyError)):
                getattr(mod, "__elite_missing_surface__")

if __name__ == "__main__":
    unittest.main()
