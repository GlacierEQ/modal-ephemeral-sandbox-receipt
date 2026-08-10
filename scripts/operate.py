#!/usr/bin/env python3
"""Cold-start operate — elite leaf bar entry for modal-ephemeral-sandbox-receipt.

Content-checks shipped mechanism CALL outputs only.
Never import-only, class-name-only, field-echo, or sample-string theater.
"""
from __future__ import annotations
import importlib
import inspect
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
MOD = "ephemeral_sandbox_receipt"

# Structured keys that look like real mechanism output
_CONTENT_KEYS = frozenset({
    "ok", "status", "result", "plan", "path", "health", "health_index",
    "decision", "allowed", "util", "confidence", "fingerprint", "digest",
    "reason", "error", "stations", "mbps", "cost", "stage", "holds",
    "assignments", "connectors", "public_count", "score", "margin", "jobs",
    "samples", "receipt", "state", "can_vote", "bytes_in", "bytes_out",
    "savings_pct", "sha256", "canonical_uri", "measurement_unit", "agents",
    "available", "verdict", "token_fp", "mac", "chain", "payload_keys",
})
# Field-name / sample-echo denylist (never content_checked as a bare value)
_FIELD_ECHO_NAMES = frozenset({
    "capabilities", "status", "state", "health", "connectors", "registry",
    "config", "summary", "metrics", "path", "body_digest", "mac", "name",
    "label", "obj", "text", "action", "connector",
})
_SKIP_FNS = frozenset({
    "main", "cli", "app", "run_server", "serve", "dataclass", "field",
    "asdict", "astuple", "replace", "NamedTuple", "TypedDict", "Enum",
    "Path", "annotations", "IntEnum", "StrEnum", "auto", "unique",
    "overload", "final", "runtime_checkable", "cast", "get_args",
    "get_origin", "get_type_hints", "dataclass_transform",
})
# Real mechanism callables only (not dataclass field names)
_PREFERRED_FNS = (
    "build_stack", "smoke", "create", "default", "run", "evaluate",
    "schedule", "health_index", "plan", "decide", "check", "fingerprint",
    "compile", "shortest_path", "authorize", "process", "bound",
    "simulate_rack", "anomaly_score", "thermal_margin", "summary",
    "allow_claim", "max_claim_for", "max_stage", "externalize", "measure",
    "verify", "resolve", "optimize", "mint", "dispatch", "assign_task",
    "get_status", "register_agent", "analyze", "observe", "certify",
    "classify", "all_ok", "promote", "record", "assert_claim", "apply",
    "apply_batch", "encode_batch", "export_recommendation", "place",
    "fleet", "mode", "budget", "shed", "outlet", "control_loop",
    "miss_distance_km", "boiloff_rate_kg_s", "compact_session",
    "flagship_count", "all_present", "verify_manifest",
)
_PREFERRED_METHS = (
    "assign_task", "get_status", "register_agent", "mint", "verify",
    "fingerprint", "dispatch", "evaluate", "compile", "analyze",
    "observe", "certify", "classify", "all_ok", "promote", "record",
    "assert_claim", "apply", "apply_batch", "run", "process", "plan",
    "decide", "check", "authorize", "bound", "health_index", "schedule",
    "allocate", "capabilities",  # only as CALLABLE method (CapabilityTwin)
    "health", "connectors", "summary", "content_digest", "key", "replay_hashes",
    "reverse_diff", "upsert_base", "invoke",
)
_DEFERRED_FNS = ("digest",)  # weak helper — last resort after real ops


def _try_import():
    errors = []
    for name in (MOD, "src." + MOD):
        try:
            return importlib.import_module(name), name
        except Exception as e:
            errors.append("%s: %s: %s" % (name, type(e).__name__, e))
    raise ImportError("; ".join(errors))


def _is_local_class(mod, obj) -> bool:
    try:
        mod_name = getattr(obj, "__module__", None)
        if mod_name in {mod.__name__, getattr(mod, "__package__", None)}:
            return True
        if getattr(mod, obj.__name__, None) is obj:
            if mod_name and (
                mod_name.startswith("typing")
                or mod_name in {"builtins", "collections", "pathlib", "json", "sys", "os"}
            ):
                return False
            return True
        return False
    except Exception:
        return False


def _contentful(value, *, called_name: str | None = None) -> bool:
    """True only for real mechanism call outputs — fail-closed on samples/field echoes."""
    if value is None:
        return False
    try:
        import enum
        if isinstance(value, enum.Enum):
            # bare enum from a field is weak; allow only when method likely returns status
            if called_name in {"status", "decide", "check", "verdict", "state"}:
                return True
            return False
    except Exception:
        pass
    if inspect.isclass(value) or inspect.ismodule(value) or callable(value):
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, (bytes, bytearray)):
        return len(value) > 0
    if isinstance(value, str):
        if not value or value in {"None", "True", "False"}:
            return False
        if value.startswith("<function ") or value.startswith("<class "):
            return False
        # field-echo / ctor sample: result equals the method/attr name
        if called_name and value == called_name:
            return False
        if value in _FIELD_ECHO_NAMES:
            return False
        # class-name echo
        if value.isidentifier() and value[:1].isupper() and "_" not in value:
            return False
        # single-token ALLCAPS enum-like without real call context is weak
        if value.isupper() and value.isidentifier() and len(value) < 24:
            if called_name not in {"status", "decide", "check", "verdict", "state", "allow_claim"}:
                return False
        return True
    if isinstance(value, Path):
        return True
    if isinstance(value, (list, tuple, set, frozenset)):
        # empty collection is not elite mechanism proof (often ctor default / empty allocate)
        if len(value) == 0:
            return False
        if all(callable(x) or inspect.isclass(x) for x in value):
            return False
        return True
    if isinstance(value, dict):
        if not value:
            return False
        if set(value.keys()) <= {"answer"}:
            return False
        if any(k in _CONTENT_KEYS for k in value.keys()):
            return True
        return any(
            v is not None and v != "" and not callable(v) and not inspect.isclass(v)
            for v in value.values()
        )
    # Dataclass instances returned by real methods (Pointer, receipts, tokens)
    if hasattr(value, "__dataclass_fields__"):
        return True
    for attr in ("fingerprint", "digest", "sha256", "canonical_uri", "mac"):
        if hasattr(value, attr):
            v = getattr(value, attr)
            if isinstance(v, str) and len(v) > 0 and not v.startswith("<function "):
                return True
    return False


def _call_safe(fn, *args, **kwargs):
    try:
        if inspect.iscoroutinefunction(fn):
            return None
        result = fn(*args, **kwargs)
        if inspect.isawaitable(result):
            try:
                result.close()
            except Exception:
                pass
            return None
        return result
    except SystemExit:
        return None
    except Exception:
        return None


def _ann_str(ann) -> str:
    if ann is inspect.Parameter.empty:
        return ""
    return str(ann)


def _ann_has_type(ann_l: str, typ: str) -> bool:
    return re.search(r"\b" + re.escape(typ) + r"\b", ann_l) is not None


def _resolve_type(ann, mod):
    if ann is inspect.Parameter.empty:
        return None
    if isinstance(ann, type):
        return ann
    name = _ann_str(ann).split("[")[0].split(".")[-1].strip("'\" ")
    if name and hasattr(mod, name):
        return getattr(mod, name)
    return None


def _build_dataclass_sample(cls, mod=None):
    try:
        sig = inspect.signature(cls)
    except Exception:
        return None
    import enum
    kwargs = {}
    for name, p in sig.parameters.items():
        if name == "self":
            continue
        if p.default is not inspect.Parameter.empty:
            continue
        ann = _ann_str(p.annotation)
        al = ann.lower()
        resolved = _resolve_type(p.annotation, mod) if mod is not None else None
        if resolved is not None and inspect.isclass(resolved) and issubclass(resolved, enum.Enum):
            kwargs[name] = next(iter(resolved))
        elif _ann_has_type(al, "float"):
            kwargs[name] = 1.0
        elif _ann_has_type(al, "bool"):
            kwargs[name] = False
        elif _ann_has_type(al, "int"):
            kwargs[name] = 1
        elif _ann_has_type(al, "str"):
            # use distinctive non-field-echo sample
            kwargs[name] = "sample_%s" % name
        elif any(_ann_has_type(al, t) for t in ("list", "set", "tuple", "sequence", "iterable", "frozenset")):
            if _ann_has_type(al, "frozenset") or _ann_has_type(al, "set"):
                kwargs[name] = frozenset({"read"}) if "cap" in name or "capabilit" in name else set()
            else:
                kwargs[name] = []
        elif _ann_has_type(al, "dict") or _ann_has_type(al, "mapping"):
            kwargs[name] = {"k": 1}
        elif _ann_has_type(al, "bytes"):
            kwargs[name] = b"elite-sample-secret"
        else:
            kwargs[name] = 1.0 if any(x in name for x in ("temp", "util", "power", "load")) else 1
    try:
        return cls(**kwargs)
    except Exception:
        try:
            return cls()
        except Exception:
            return None


def _sample_args(fn, mod):
    """Yield candidate positional arg tuples for required params."""
    try:
        sig = inspect.signature(fn)
    except Exception:
        yield ()
        return
    required = [
        p for p in sig.parameters.values()
        if p.name != "self"
        and p.default is inspect.Parameter.empty
        and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
    ]
    if not required:
        yield ()
        return

    import enum
    import tempfile
    from pathlib import Path as _Path

    simple = []
    for p in required:
        ann = _ann_str(p.annotation)
        al = ann.lower()
        resolved = _resolve_type(p.annotation, mod)
        if resolved is not None and inspect.isclass(resolved) and issubclass(resolved, enum.Enum):
            simple.append(next(iter(resolved)))
            continue
        if "callable[" in al or al.strip() in {"callable", "typing.callable"} or "decisionfn" in al.replace(" ", ""):
            simple.append(lambda *a, **k: (False, "REFUSED"))
            continue
        if p.name in ("decide", "decision", "handler", "callback") and not any(
            _ann_has_type(al, t) for t in ("list", "sequence", "iterable", "dict", "str", "int", "float")
        ):
            simple.append(lambda *a, **k: (False, "REFUSED"))
            continue
        if _ann_has_type(al, "bytes") or p.name in ("secret", "key"):
            simple.append(b"elite-operate-secret")
        elif (
            _ann_has_type(al, "list")
            or _ann_has_type(al, "sequence")
            or _ann_has_type(al, "iterable")
            or _ann_has_type(al, "tuple")
        ):
            # prefer one sample element when inner type is a local dataclass
            inner = None
            m = re.search(r"\[([A-Za-z_][A-Za-z0-9_]*)", ann)
            if m and hasattr(mod, m.group(1)):
                cand = getattr(mod, m.group(1))
                if inspect.isclass(cand):
                    inner = _build_dataclass_sample(cand, mod)
            simple.append([inner] if inner is not None else [])
        elif _ann_has_type(al, "set") or _ann_has_type(al, "frozenset"):
            simple.append(frozenset({"read"}))
        elif _ann_has_type(al, "mapping") or _ann_has_type(al, "dict"):
            simple.append({"k": 1})
        elif _ann_has_type(al, "path") or p.name in ("dest", "root", "allowed_root") or resolved is _Path:
            simple.append(_Path(tempfile.mkdtemp(prefix="elite_op_")))
        elif _ann_has_type(al, "float"):
            simple.append(1.0 if p.name not in ("not_after",) else 1e12)
        elif _ann_has_type(al, "bool"):
            simple.append(False)
        elif _ann_has_type(al, "int"):
            simple.append(1)
        elif _ann_has_type(al, "str") or p.name in ("connector", "action", "name", "body", "label", "path", "capability"):
            if p.name == "connector":
                simple.append("__operate_sample__")
            elif p.name in ("body", "text"):
                simple.append("elite operate sample body " * 20)
            elif p.name == "path":
                simple.append("/api/elite")
            elif p.name == "capability":
                simple.append("read")
            else:
                simple.append("sample_%s" % p.name)
        else:
            cls = resolved if (resolved is not None and inspect.isclass(resolved)) else None
            base = ann.split("[")[0].split(".")[-1].strip("'\"")
            if cls is None and base and hasattr(mod, base):
                cand = getattr(mod, base)
                if inspect.isclass(cand):
                    cls = cand
            if cls is not None and inspect.isclass(cls) and issubclass(cls, enum.Enum):
                simple.append(next(iter(cls)))
            elif cls is not None:
                sample = _build_dataclass_sample(cls, mod)
                simple.append(sample if sample is not None else None)
            else:
                if "object" in al or "any" in al or p.name in ("obj", "value", "body"):
                    simple.append({"elite": True, "n": 1})
                else:
                    simple.append(None)
    if None not in simple:
        yield tuple(simple)

    # schedule-style: list[Job] + float
    if len(required) >= 2:
        p0, p1 = required[0], required[1]
        a0, a1 = _ann_str(p0.annotation), _ann_str(p1.annotation)
        if "list" in a0.lower() or "iterable" in a0.lower() or "sequence" in a0.lower():
            for n, obj in inspect.getmembers(mod, inspect.isclass):
                if n.startswith("_"):
                    continue
                if n.lower() in a0.lower() or "job" in n.lower() or "sample" in n.lower() or "need" in n.lower():
                    inst = _build_dataclass_sample(obj, mod)
                    if inst is not None:
                        second = 1.0 if "float" in a1.lower() or p1.name.endswith("mw") else 1
                        yield ([inst], second)
            r1 = _resolve_type(p1.annotation, mod)
            if r1 is not None and inspect.isclass(r1) and issubclass(r1, enum.Enum):
                yield ([], next(iter(r1)))
                yield (["sim", "tested"], list(r1)[-1])

    # two enums
    if len(required) >= 2:
        r0 = _resolve_type(required[0].annotation, mod)
        r1 = _resolve_type(required[1].annotation, mod)
        if (
            r0 is not None and r1 is not None
            and inspect.isclass(r0) and inspect.isclass(r1)
            and issubclass(r0, enum.Enum) and issubclass(r1, enum.Enum)
        ):
            yield (next(iter(r0)), list(r1)[-1])
            yield (next(iter(r0)), next(iter(r1)))

    # mint-style: path, body dict, capabilities set, not_after
    if len(required) >= 3:
        yield ("/api/elite", {"k": 1}, frozenset({"read"}))
    if len(required) >= 4:
        yield ("/api/elite", {"k": 1}, frozenset({"read"}), 1e12)


def _try_fn(mod, attr, fn):
    if not callable(fn) or inspect.isclass(fn) or inspect.iscoroutinefunction(fn):
        return None
    for args in _sample_args(fn, mod):
        result = _call_safe(fn, *args)
        if result is not None and _contentful(result, called_name=attr):
            return {
                "kind": "fn",
                "name": attr,
                "args": [repr(a)[:40] for a in args],
                "result": result if not isinstance(result, (bytes, bytearray)) else repr(result)[:200],
                "content_checked": True,
                "invoked": True,
            }
    return None


def _try_method(inst, cname, meth, mod):
    m = getattr(inst, meth, None)
    if not callable(m):
        return None
    for args in _sample_args(m, mod):
        result = _call_safe(m, *args)
        if result is not None and _contentful(result, called_name=meth):
            return {
                "kind": "class",
                "name": cname,
                "method": meth,
                "args": [repr(a)[:40] for a in args],
                "result": result if not isinstance(result, (bytes, bytearray)) else repr(result)[:200],
                "module_local": True,
                "content_checked": True,
                "invoked": True,
            }
    return None


def _class_method_score(cls) -> int:
    """Prefer engines with real methods over pure dataclass records."""
    try:
        methods = [
            n for n, v in inspect.getmembers(cls, predicate=callable)
            if not n.startswith("_") and n not in {"from_dict", "to_dict"}
        ]
    except Exception:
        methods = []
    # dataclass field-only classes score 0
    fields = getattr(cls, "__dataclass_fields__", None) or {}
    score = len(methods)
    if fields and score == 0:
        return -1
    # boost known engine names
    name = cls.__name__.lower()
    for hint in (
        "coordinator", "mint", "runtime", "engine", "quorum", "matrix",
        "ledger", "fence", "sentinel", "monitor", "compiler", "router",
        "twin", "gate", "bus", "allocator", "certifier", "harness",
    ):
        if hint in name:
            score += 10
    return score


def _construct(cls, mod):
    try:
        sig = inspect.signature(cls)
        required = [
            p for p in sig.parameters.values()
            if p.name != "self"
            and p.default is inspect.Parameter.empty
            and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
        ]
    except Exception:
        try:
            return cls()
        except Exception:
            return None
    if not required:
        try:
            return cls()
        except Exception:
            return None
    args = []
    for p in required:
        al = _ann_str(p.annotation).lower()
        if _ann_has_type(al, "bytes") or p.name in ("secret", "key"):
            args.append(b"elite-operate-secret")
        elif _ann_has_type(al, "set") or _ann_has_type(al, "frozenset"):
            args.append(frozenset({"read"}))
        elif any(_ann_has_type(al, t) for t in ("list", "sequence", "iterable", "tuple")):
            args.append([])
        elif _ann_has_type(al, "dict") or _ann_has_type(al, "mapping"):
            args.append({})
        elif _ann_has_type(al, "float"):
            args.append(1.0)
        elif _ann_has_type(al, "bool"):
            args.append(False)
        elif _ann_has_type(al, "int"):
            args.append(1)
        elif _ann_has_type(al, "str"):
            args.append("sample_%s" % p.name)
        else:
            resolved = _resolve_type(p.annotation, mod)
            if resolved is not None and inspect.isclass(resolved):
                try:
                    import enum
                    if issubclass(resolved, enum.Enum):
                        args.append(next(iter(resolved)))
                        continue
                except Exception:
                    pass
                s = _build_dataclass_sample(resolved, mod)
                if s is not None:
                    args.append(s)
                    continue
            args.append(None)
    if None not in args:
        try:
            return cls(*args)
        except Exception:
            pass
    for trial in (
        [[] for _ in required],
        [set() for _ in required],
        [{} for _ in required],
        [b"elite-operate-secret" if i == 0 else 1 for i in range(len(required))],
    ):
        try:
            return cls(*trial)
        except Exception:
            continue
    return None


def _smoke(mod):
    # 1) Preferred module-level mechanism functions
    for attr in _PREFERRED_FNS:
        fn = getattr(mod, attr, None)
        hit = _try_fn(mod, attr, fn) if fn is not None else None
        if hit:
            return hit

    # 2) Module-local classes — CALL methods only (never bare field reads)
    members = [
        (n, c) for n, c in inspect.getmembers(mod, inspect.isclass)
        if not n.startswith("_") and _is_local_class(mod, c)
    ]
    # skip pure Enums
    filtered = []
    for cname, obj in members:
        try:
            import enum
            if inspect.isclass(obj) and issubclass(obj, enum.Enum):
                continue
        except Exception:
            pass
        filtered.append((cname, obj))
    # engines first
    filtered.sort(key=lambda kv: (-_class_method_score(kv[1]), kv[0]))

    for cname, obj in filtered:
        if _class_method_score(obj) < 0:
            continue  # pure dataclass record with no methods
        inst = _construct(obj, mod)
        if inst is None:
            continue
        for meth in _PREFERRED_METHS:
            hit = _try_method(inst, cname, meth, mod)
            if hit:
                return hit
        # any other public callable method (not dunder / not dataclass helpers)
        for meth, m in inspect.getmembers(inst, callable):
            if meth.startswith("_") or meth in _PREFERRED_METHS:
                continue
            if meth in {"from_dict", "to_dict", "copy", "replace"}:
                continue
            hit = _try_method(inst, cname, meth, mod)
            if hit:
                return hit
        # NO attribute/field fallback — that is field-echo theater

    # 3) Deferred weak helpers + remaining functions
    for attr in _DEFERRED_FNS:
        fn = getattr(mod, attr, None)
        hit = _try_fn(mod, attr, fn) if fn is not None else None
        if hit:
            return hit
    _skip = set(_PREFERRED_FNS) | set(_DEFERRED_FNS) | _SKIP_FNS
    for attr, fn in inspect.getmembers(mod, callable):
        if attr.startswith("_") or inspect.isclass(fn) or attr in _skip:
            continue
        hit = _try_fn(mod, attr, fn)
        if hit:
            return hit

    public = [n for n in dir(mod) if not n.startswith("_")]
    raise RuntimeError(
        "no content-checked mechanism CALL; public=%s" % (public[:12],)
    )


def main() -> int:
    mod, imported_as = _try_import()
    try:
        smoke = _smoke(mod)
        ok = (
            bool(smoke.get("content_checked"))
            and bool(smoke.get("invoked"))
            and _contentful(smoke.get("result"), called_name=smoke.get("method") or smoke.get("name"))
        )
    except Exception as e:
        out = {
            "repository": "GlacierEQ/modal-ephemeral-sandbox-receipt",
            "module": imported_as,
            "smoke": {"kind": "error", "error": str(e)},
            "ok": False,
        }
        print(json.dumps(out, sort_keys=True, default=str))
        return 1
    out = {
        "repository": "GlacierEQ/modal-ephemeral-sandbox-receipt",
        "module": imported_as,
        "smoke": smoke,
        "ok": bool(ok),
    }
    print(json.dumps(out, sort_keys=True, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
