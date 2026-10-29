"""Package call graphs from Jelly, PyCG and the IR, merged into one graph."""
import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

FuncKey = Tuple[str, int]


def _find_pycg() -> Optional[str]:
    """Locate the pycg executable."""
    cand = [os.environ.get("PYCG_BIN"), shutil.which("pycg")]
    for c in cand:
        if c and os.path.exists(c):
            return c
    return None


def _find_jelly() -> Optional[str]:
    """Locate the jelly executable."""
    cand = [os.environ.get("JELLY_BIN"), shutil.which("jelly")]
    for c in cand:
        if c and os.path.exists(c):
            return c
    return None


class CallGraph:
    """Caller edges keyed by (file, function id)."""
    def __init__(self):
        """Create an empty graph."""
        self.callers: Dict[FuncKey, List[Dict[str, Any]]] = defaultdict(list)
        self.callees: Dict[FuncKey, List[FuncKey]] = defaultdict(list)
        self.providers: List[str] = []
        self.errors: Dict[str, str] = {}

    def add_edge(self, caller: FuncKey, callee: FuncKey, line: int, stmt: Optional[int], via: str):
        """Add a caller edge."""
        if caller == callee:
            return
        for e in self.callers[callee]:
            if e["file"] == caller[0] and e["fid"] == caller[1] and e["line"] == line:
                return
        self.callers[callee].append({"file": caller[0], "fid": caller[1], "stmt": stmt, "line": line, "via": via})
        self.callees[caller].append(callee)

    def n_edges(self) -> int:
        """Number of edges."""
        return sum(len(v) for v in self.callers.values())


def _stmt_at_line(ir: Dict[str, Any], fid: int, line: int) -> Optional[int]:
    """Innermost statement of a function covering a line."""
    best, best_span = None, None
    for s in ir["statements"]:
        if s["func"] != fid or not (s["start"] <= line <= s["end"]):
            continue
        span = s["end"] - s["start"]
        if best is None or span < best_span:
            best, best_span = s["id"], span
    return best


def _func_at_line(ir: Dict[str, Any], line: int) -> int:
    """Innermost function containing a line."""
    best, best_span = 0, None
    for f in ir["functions"]:
        if f["id"] == 0 or not (f["start"] <= line <= f["end"]):
            continue
        span = f["end"] - f["start"]
        if best_span is None or span < best_span:
            best, best_span = f["id"], span
    return best


def build_ir_callgraph(irs: Dict[str, Dict[str, Any]], graph: Optional[CallGraph] = None) -> CallGraph:
    """Add name-resolved edges from the IR."""
    graph = graph or CallGraph()
    by_name: Dict[str, List[FuncKey]] = defaultdict(list)
    for file, ir in irs.items():
        for f in ir["functions"]:
            if f["id"] != 0:
                by_name[f["name"]].append((file, f["id"]))
                by_name[f["qualname"]].append((file, f["id"]))
    for file, ir in irs.items():
        for s in ir["statements"]:
            for c in s["calls"]:
                base = c.replace("()", "")
                last = base.split(".")[-1]
                cands = by_name.get(base) or by_name.get(last) or []
                same_file = [k for k in cands if k[0] == file]
                for callee in (same_file or cands)[:4]:
                    graph.add_edge((file, s["func"]), callee, s["start"], s["id"], "ir")
        for f in ir["functions"]:
            if f.get("role") in ("callarg", "iife") and f.get("stmt") is not None and f.get("parent") is not None:
                st = ir["statements"][f["stmt"]]
                graph.add_edge((file, f["parent"]), (file, f["id"]), st["start"], st["id"], "ir-callback")
    graph.providers.append("ir")
    return graph


def build_jelly_callgraph(package_dir: str, files: List[str], irs: Dict[str, Dict[str, Any]],
                          graph: Optional[CallGraph] = None, timeout: int = 120) -> CallGraph:
    """Add edges from Jelly."""
    graph = graph or CallGraph()
    jelly = _find_jelly()
    if not jelly:
        graph.errors["jelly"] = "jelly binary not found"
        return graph
    js_files = [f for f in files if f.endswith((".js", ".mjs", ".cjs"))]
    if not js_files:
        return graph
    with tempfile.TemporaryDirectory(prefix="jelly_") as td:
        out = os.path.join(td, "cg.json")
        cmd = [jelly, "-j", out, "--ignore-dependencies", "--ignore-unresolved", "-i", str(timeout),
               "-b", package_dir, "-l", "error"] + [os.path.relpath(f, package_dir) for f in js_files]
        try:
            subprocess.run(cmd, cwd=package_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout + 30, check=False)
        except subprocess.TimeoutExpired:
            graph.errors["jelly"] = "timeout"
            return graph
        except Exception as e:
            graph.errors["jelly"] = str(e)
            return graph
        if not os.path.exists(out):
            graph.errors["jelly"] = "no output"
            return graph
        try:
            with open(out, "r", encoding="utf-8") as fh:
                cg = json.load(fh)
        except Exception as e:
            graph.errors["jelly"] = f"bad json: {e}"
            return graph

    def loc(spec: str):
        """Parse a Jelly location."""
        p = spec.split(":")
        return int(p[0]), int(p[1]), int(p[3])

    def key_for(spec: str) -> Optional[FuncKey]:
        """Map a Jelly function to (file, function id)."""
        fi, s, e = loc(spec)
        if fi >= len(cg.get("files", [])):
            return None
        file = os.path.normpath(os.path.join(package_dir, cg["files"][fi]))
        ir = irs.get(file)
        if ir is None:
            return None
        if s <= 1 and e >= ir["n_lines"] - 1:
            return (file, 0)
        best = None
        for f in ir["functions"]:
            if f["id"] != 0 and f["start"] == s:
                if best is None or abs(f["end"] - e) < abs(best["end"] - e):
                    best = f
        if best is None:
            return (file, _func_at_line(ir, s))
        return (file, best["id"])

    funcs = {int(k): key_for(v) for k, v in cg.get("functions", {}).items()}
    calls = {int(k): v for k, v in cg.get("calls", {}).items()}
    n = 0
    for call_id, fun_id in cg.get("call2fun", []):
        spec = calls.get(call_id)
        callee = funcs.get(fun_id)
        if not spec or not callee:
            continue
        fi, line, _ = loc(spec)
        file = os.path.normpath(os.path.join(package_dir, cg["files"][fi]))
        ir = irs.get(file)
        if ir is None:
            continue
        caller_fid = _func_at_line(ir, line)
        stmt = _stmt_at_line(ir, caller_fid, line)
        graph.add_edge((file, caller_fid), callee, line, stmt, "jelly")
        n += 1
    for a, b in cg.get("fun2fun", []):
        ca, cb = funcs.get(a), funcs.get(b)
        if ca and cb and cb not in graph.callees.get(ca, []):
            graph.add_edge(ca, cb, irs[cb[0]]["functions"][cb[1]]["start"], None, "jelly")
            n += 1
    graph.providers.append(f"jelly({n})")
    return graph


def build_pycg_callgraph(package_dir: str, files: List[str], irs: Dict[str, Dict[str, Any]],
                         graph: Optional[CallGraph] = None, timeout: int = 120) -> CallGraph:
    """Add edges from PyCG."""
    graph = graph or CallGraph()
    pycg = _find_pycg()
    if not pycg:
        graph.errors["pycg"] = "pycg binary not found (set PYCG_BIN)"
        return graph
    py_files = [f for f in files if f.endswith(".py")]
    if not py_files:
        return graph

    def run(cmd: List[str], cwd: str) -> Optional[Dict[str, List[str]]]:
        """Run a command with a timeout."""
        with tempfile.TemporaryDirectory(prefix="pycg_") as td:
            out = os.path.join(td, "cg.json")
            try:
                subprocess.run(cmd + ["-o", out], cwd=cwd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                graph.errors["pycg"] = "timeout"
                return None
            except Exception as e:
                graph.errors["pycg"] = str(e)
                return None
            if not os.path.exists(out):
                return None
            try:
                with open(out, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                return None

    cg = run([pycg, "--package", package_dir] + py_files, package_dir)
    if cg is None:
        graph.errors.setdefault("pycg", "package-level run failed; using per-file runs")
        cg = {}
        for f in py_files:
            part = run([pycg, f], os.path.dirname(f)) or {}
            for k, v in part.items():
                cg.setdefault(k, []).extend(v)

    qual_index: Dict[str, List[FuncKey]] = defaultdict(list)
    for file, ir in irs.items():
        rel = os.path.relpath(file, package_dir)
        mod = rel[:-3].replace(os.sep, ".")
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        for f in ir["functions"]:
            if f["id"] == 0:
                qual_index[mod].append((file, 0))
                qual_index[os.path.basename(file)[:-3]].append((file, 0))
            else:
                qual_index[f"{mod}.{f['qualname']}"].append((file, f["id"]))
                qual_index[f['qualname']].append((file, f["id"]))
                qual_index[f"{os.path.basename(file)[:-3]}.{f['qualname']}"].append((file, f["id"]))

    def resolve(name: str) -> Optional[FuncKey]:
        """Map a PyCG name to (file, function id)."""
        if name in qual_index:
            return qual_index[name][0]
        parts = name.split(".")
        for i in range(1, len(parts)):
            cand = ".".join(parts[i:])
            if cand in qual_index:
                return qual_index[cand][0]
        return None

    n = 0
    for caller_name, callees in cg.items():
        caller = resolve(caller_name)
        if caller is None:
            continue
        ir = irs[caller[0]]
        for callee_name in callees:
            callee = resolve(callee_name)
            if callee is None or callee == caller:
                continue
            short = callee_name.split(".")[-1]
            stmt_id, line = None, ir["functions"][caller[1]]["start"]
            for s in ir["statements"]:
                if s["func"] == caller[1] and any(c.split(".")[-1].replace("()", "") == short for c in s["calls"]):
                    stmt_id, line = s["id"], s["start"]
                    break
            graph.add_edge(caller, callee, line, stmt_id, "pycg")
            n += 1
    graph.providers.append(f"pycg({n})")
    return graph


def build_callgraph(package_dir: str, package_manager: str, irs: Dict[str, Dict[str, Any]],
                    timeout: int = 120) -> CallGraph:
    """Build the merged call graph of a package."""
    graph = CallGraph()
    files = list(irs.keys())
    try:
        if package_manager == "npm":
            build_jelly_callgraph(package_dir, files, irs, graph, timeout=timeout)
        else:
            build_pycg_callgraph(package_dir, files, irs, graph, timeout=timeout)
    except Exception as e:
        graph.errors["tool"] = str(e)
    build_ir_callgraph(irs, graph)
    logger.info(f"call graph: providers={graph.providers} edges={graph.n_edges()} errors={graph.errors}")
    return graph
