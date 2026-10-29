"""Static sensitive-code slicer: backward data and control slicing from sensitive API call sites, extended to callers through the call graph."""
import json
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from Codes.Detect.static.py_ir import build_ir as build_py_ir
from Codes.Detect.static.callgraph import build_callgraph, CallGraph

logger = logging.getLogger(__name__)

JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts")
SHELL_EXT = (".sh", ".bat", ".cmd", ".ps1")
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall",
                 "uninstall", "postuninstall", "prepack", "postpack")
FuncKey = Tuple[str, int]
COMPOUND_KINDS = {"if", "for", "while", "try", "trystar", "with", "forin", "forof", "dowhile", "switch", "asyncfor",
                  "asyncwith", "function", "functiondef", "asyncfunctiondef", "match", "block", "labeled", "class", "classdef"}


class SensitiveAPIs:
    """Sensitive API catalogue with import-alias resolution."""

    def __init__(self, path: Optional[str] = None):
        """Load sensitive_apis.json."""
        with open(path or HERE / "sensitive_apis.json", "r", encoding="utf-8") as f:
            cat = json.load(f)
        self.cat = {}
        for lang in ("python", "javascript"):
            c = cat[lang]
            mods = {m: k for k, v in c["modules"].items() for m in v}
            mems = {m: k for k, v in c["members"].items() for m in v}
            glob = {m: k for k, v in c["globals"].items() for m in v}
            self.cat[lang] = (mods, mems, glob)

    @staticmethod
    def _norm_module(m: str) -> str:
        """Normalise a module name."""
        m = m.strip()
        if m.startswith("node:"):
            m = m[5:]
        return m

    def resolve(self, lang: str, name: str, imports: Dict[str, str]) -> Optional[Tuple[str, str]]:
        """Return (api, category) for a call or member string, or None."""
        mods, mems, glob = self.cat[lang]
        name = name.replace("()", "")
        m = re.match(r"^require\('([^']+)'\)(?:\.(.*))?$", name)
        if m:
            base = self._norm_module(m.group(1))
            rest = m.group(2) or ""
            name = base + ("." + rest if rest else "")
            parts = name.split(".")
        else:
            parts = name.split(".")
            if parts[0] in imports:
                target = self._norm_module(imports[parts[0]])
                if target.startswith("."):
                    return None
                parts = target.split(".") + parts[1:]
        if not parts:
            return None
        for i in range(min(len(parts), 3), 0, -1):
            cand = ".".join(parts[:i])
            if cand in mods:
                return (".".join(parts), mods[cand])
        for i in range(len(parts), 1, -1):
            cand = ".".join(parts[:i])
            if cand in mems:
                return (".".join(parts), mems[cand])
        if len(parts) == 1 and parts[0] in glob and parts[0] not in ("require", "import"):
            return (parts[0], glob[parts[0]])
        return None


INDICATORS = [
    ("indicator:url", re.compile(r"https?://(?!(?:localhost|127\.0\.0\.1|registry\.npmjs\.org|www\.npmjs\.com|github\.com/[\w.-]+/[\w.-]+/?(?:$|[\"'#?])|pypi\.org|example\.com|schemastore|json-schema|www\.w3\.org))[\w.-]+(?::\d+)?[^\s\"'`]*")),
    ("indicator:ip", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\w.])")),
    ("indicator:hex-obfuscation", re.compile(r"\b_0x[0-9a-f]{4,}\b")),
    ("indicator:encoded-blob", re.compile(r"[\"'`][A-Za-z0-9+/=]{60,}[\"'`]|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}|[\"'`](?:[0-9a-f]{2}){24,}[\"'`]")),
    ("indicator:charcode", re.compile(r"String\.fromCharCode|\bchr\(|\.decode\(['\"]hex|bytes\.fromhex|\bunhexlify")),
    ("indicator:dynamic-require", re.compile(r"\brequire\((?![\"'`])[^)]*\)|__import__\((?![\"'])|importlib\.import_module\((?![\"'])")),
    ("indicator:shell-command", re.compile(r"[\"'`](?:[^\"'`]*\b(?:curl|wget|chmod \+x|powershell|cmd\.exe|/bin/(?:ba)?sh|certutil|bitsadmin)\b[^\"'`]*)[\"'`]")),
    ("indicator:secret-env", re.compile(r"\b(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|AWS_ACCESS|AWS_SECRET|DISCORD)[A-Z_]*)\b")),
]
WEAK_INDICATORS = {"indicator:charcode", "indicator:secret-env", "indicator:ip"}
LOCAL_URL_SKIP = re.compile(r"^\s*(//|#|/\*|\*)")


class StaticCodeSlicer:
    """Slice the sensitive code of a package and summarise each slice."""
    def __init__(self, llm_agent=None, max_lines: int = 120, max_caller_depth: int = 3,
                 max_callers: int = 3, max_slices_per_file: int = 25, callgraph_timeout: int = 120,
                 small_callee_lines: int = 40):
        """Set slicing limits and the optional LLM agent."""
        self.llm_agent = llm_agent
        self.max_lines = max_lines
        self.max_caller_depth = max_caller_depth
        self.max_callers = max_callers
        self.max_slices_per_file = max_slices_per_file
        self.callgraph_timeout = callgraph_timeout
        self.small_callee_lines = small_callee_lines
        self.apis = SensitiveAPIs()
        self.summary_prompt = (HERE / "behavior_summary_prompt.txt").read_text(encoding="utf-8")
        self.package_path: Optional[str] = None
        self.package_manager: Optional[str] = None
        self.irs: Dict[str, Dict[str, Any]] = {}
        self.sources: Dict[str, List[str]] = {}
        self.graph: Optional[CallGraph] = None
        self.hook_files: Set[str] = set()
        self.stats: Dict[str, Any] = {}

    def prepare_package(self, package_path: str, package_manager: str, code_files: Optional[List[str]] = None):
        """Build the IR and the call graph of a package."""
        self.package_path = os.path.abspath(os.path.normpath(str(package_path)))
        self.package_manager = package_manager
        self.irs, self.sources, self.hook_files = {}, {}, set()
        if code_files is None:
            code_files = self._scan(self.package_path, package_manager)
        code_files = [os.path.abspath(os.path.normpath(str(f))) for f in code_files]
        js = [f for f in code_files if f.endswith(JS_EXT) and os.path.getsize(f) <= 1_500_000]
        py = [f for f in code_files if f.endswith(".py") and os.path.getsize(f) <= 1_500_000]
        for f in code_files:
            if (f.endswith(JS_EXT) or f.endswith(".py")) and os.path.getsize(f) > 1_500_000:
                self.irs[f] = {"file": f, "lang": "py" if f.endswith(".py") else "js", "parse_ok": False, "error": "file too large for the parser",
                               "n_lines": 0, "functions": [{"id": 0, "name": "<module>", "qualname": "<module>", "start": 1, "end": 1, "parent": None, "params": []}], "statements": []}
        for f in py:
            try:
                self.irs[f] = build_py_ir(f)
            except Exception as e:
                self.irs[f] = {"file": f, "lang": "py", "parse_ok": False, "error": str(e), "n_lines": 0,
                               "functions": [{"id": 0, "name": "<module>", "qualname": "<module>", "start": 1, "end": 1, "parent": None, "params": []}],
                               "statements": []}
        if js:
            for ir in self._build_js_irs(js):
                self.irs[os.path.normpath(ir["file"])] = ir
        for f in list(self.irs):
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    self.sources[f] = fh.read().split("\n")
            except Exception:
                self.sources[f] = []
        self.hook_files = self._install_hook_files()
        try:
            self.graph = build_callgraph(self.package_path, package_manager, self.irs, timeout=self.callgraph_timeout)
        except Exception as e:
            logger.warning(f"call graph failed, IR-only: {e}")
            from Codes.Detect.static.callgraph import build_ir_callgraph
            self.graph = build_ir_callgraph(self.irs)
        self.stats = {"files": len(code_files), "parsed": sum(1 for i in self.irs.values() if i["parse_ok"]),
                      "callgraph_providers": self.graph.providers, "callgraph_edges": self.graph.n_edges(),
                      "callgraph_errors": self.graph.errors}
        logger.info(f"static slicer prepared: {self.stats}")

    @staticmethod
    def _scan(package_path: str, package_manager: str) -> List[str]:
        """Code files of a package to slice."""
        exclude = {"venv", "env", ".venv", "__pycache__", ".git", "node_modules", ".next", ".nuxt", "coverage", ".cache"}
        out = []
        for root, dirs, files in os.walk(package_path):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fn in files:
                p = os.path.join(root, fn)
                if package_manager == "pypi" and fn.endswith(".py"):
                    out.append(p)
                elif package_manager == "npm" and (fn.endswith(JS_EXT) or fn == "package.json" or fn.endswith(SHELL_EXT)):
                    out.append(p)
        return out

    def _build_js_irs(self, files: List[str]) -> List[Dict[str, Any]]:
        """Build the IR of JavaScript files."""
        irs = []
        for i in range(0, len(files), 200):
            chunk = files[i:i + 200]
            try:
                r = subprocess.run(["node", str(HERE / "js_ir.js")] + chunk, capture_output=True, text=True, timeout=300)
                if r.returncode == 0 and r.stdout.strip():
                    irs.extend(json.loads(r.stdout))
                    continue
                err = r.stderr[-300:]
            except Exception as e:
                err = str(e)
            for f in chunk:
                irs.append({"file": f, "lang": "js", "parse_ok": False, "error": err, "n_lines": 0,
                            "functions": [{"id": 0, "name": "<module>", "qualname": "<module>", "start": 1, "end": 1, "parent": None, "params": []}],
                            "statements": []})
        return irs

    def _install_hook_files(self) -> Set[str]:
        """Files run by install hooks or setup.py."""
        hooks: Set[str] = set()
        if self.package_manager == "pypi":
            for f in self.irs:
                if os.path.basename(f) == "setup.py":
                    hooks.add(f)
            return hooks
        for root, dirs, files in os.walk(self.package_path):
            dirs[:] = [d for d in dirs if d != "node_modules"]
            if "package.json" in files:
                pj = os.path.join(root, "package.json")
                try:
                    with open(pj, "r", encoding="utf-8", errors="ignore") as fh:
                        data = json.load(fh)
                    scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
                    for k, v in scripts.items():
                        if k in INSTALL_HOOKS and isinstance(v, str):
                            for tok in re.findall(r"(?<![\w@-])(?:\./)?[\w./@-]+", v):
                                if tok in ("node", "sh", "bash", "npm", "npx", "curl", "wget", "python", "python3"):
                                    continue
                                for cand in (tok, tok + ".js", os.path.join(tok, "index.js")):
                                    cand = os.path.normpath(os.path.join(root, cand))
                                    if cand in self.irs:
                                        hooks.add(cand)
                except Exception:
                    pass
        return hooks

    def slice_package(self, package_path: str, package_manager: str = "pypi") -> Dict[str, Any]:
        """Slice every file of a package."""
        self.prepare_package(package_path, package_manager)
        files = sorted(set(list(self.irs.keys()) + self._scan(self.package_path, package_manager)))
        return {"files": [self.slice_file(f) for f in files], "stats": self.stats}

    def slice_file(self, file_path: str) -> Dict[str, Any]:
        """Slice one file."""
        file_path = os.path.abspath(os.path.normpath(str(file_path)))
        if self.package_path is None or not file_path.startswith(self.package_path):
            pm = "pypi" if file_path.endswith(".py") else "npm"
            self.prepare_package(os.path.dirname(file_path), pm, [file_path])
        try:
            base = os.path.basename(file_path)
            if base == "package.json":
                slices = self._slice_package_json(file_path)
            elif file_path.endswith(SHELL_EXT):
                slices = self._slice_shell(file_path)
            elif file_path in self.irs:
                ir = self.irs[file_path]
                slices = self._slice_ir(file_path) if ir["parse_ok"] else self._slice_unparsed(file_path)
            else:
                slices = []
            for i, s in enumerate(slices, 1):
                s["slice_id"] = f"{Path(file_path).stem}_slice_{i}"
                s["file_path"] = file_path
                if not s.get("behavior_summary"):
                    s["behavior_summary"] = self._summarize(s)
            return {"file_path": file_path, "status": "success", "slices": slices,
                    "analysis_summary": f"{len(slices)} static slice(s); criteria: sensitive API call sites",
                    "extraction_timestamp": datetime.now().isoformat(),
                    "original_lines": len(self.sources.get(file_path, [])), "error": None, "slicer": "static"}
        except Exception as e:
            logger.exception(f"static slicing failed for {file_path}")
            return {"file_path": file_path, "status": "error", "slices": [], "error": str(e),
                    "extraction_timestamp": datetime.now().isoformat(), "slicer": "static"}

    def _scope_imports(self, ir: Dict[str, Any], fid: int) -> Dict[str, str]:
        """Import aliases visible inside a function."""
        chain = []
        f = fid
        while f is not None:
            chain.append(f)
            f = ir["functions"][f]["parent"]
        imports: Dict[str, str] = {}
        for s in ir["statements"]:
            if s["func"] in chain and s["imports"]:
                imports.update(s["imports"])
        return imports

    def _criteria(self, ir: Dict[str, Any]) -> Dict[int, List[Tuple[str, str]]]:
        """Slicing criteria: statements that hit a sensitive API or a suspicious indicator."""
        lang = "python" if ir["lang"] == "py" else "javascript"
        cache: Dict[int, Dict[str, str]] = {}
        out: Dict[int, List[Tuple[str, str]]] = {}
        for s in ir["statements"]:
            if s["kind"] in ("import", "importfrom", "function", "functiondef", "asyncfunctiondef", "class", "classdef"):
                continue
            if s["func"] not in cache:
                cache[s["func"]] = self._scope_imports(ir, s["func"])
            imports = cache[s["func"]]
            hits: List[Tuple[str, str]] = []
            names = list(s["calls"]) + [m for m in s["members"] if m not in s["calls"]]
            for n in names:
                if n in ("require", "import"):
                    continue
                r = self.apis.resolve(lang, n, imports)
                if r:
                    hits.append(r)
            src = self.sources.get(ir["file"], [])
            if src and s["end"] - s["start"] <= 400:
                text = "\n".join(l for l in src[s["start"] - 1:s["end"]] if not LOCAL_URL_SKIP.match(l))
                if len(text) <= 200000:
                    ind = [(name, "indicator") for name, pat in INDICATORS if pat.search(text)]
                    strong = [h for h in ind if h[0] not in WEAK_INDICATORS]
                    if hits or strong or len(ind) >= 2:
                        hits.extend(ind)
            if hits:
                if s["imports"] and not s["calls"] and not [m for m in s["members"] if "require" not in m]:
                    continue
                if all(h[0].split(".")[0] in s["imports"].values() and len(h[0].split(".")) == 1 for h in hits) and s["imports"]:
                    continue
                out[s["id"]] = sorted(set(hits))
        return out

    def _backward(self, file: str, start_stmts: List[int], depth: int,
                  acc: Dict[str, Dict[str, Set[int]]], chain: List[str], budget: List[int]):
        """Backward data and control slice, extended to callers."""
        ir = self.irs[file]
        stmts = ir["statements"]
        by_id = {s["id"]: s for s in stmts}
        fa = acc.setdefault(file, {"full": set(), "header": set()})
        if not start_stmts:
            return
        fid = by_id[start_stmts[0]]["func"]
        fdef = ir["functions"][fid]
        params = set(fdef.get("params", []))
        defs_in_func: Dict[str, List[int]] = defaultdict(list)
        defs_in_module: Dict[str, List[int]] = defaultdict(list)
        func_by_name: Dict[str, Dict[str, Any]] = {}
        for f in ir["functions"]:
            if f["id"] != 0 and "stmt" in f:
                func_by_name.setdefault(f["name"], f)
        for s in stmts:
            for d in s["defs"]:
                if s["func"] == fid:
                    defs_in_func[d].append(s["id"])
                if s["func"] == 0:
                    defs_in_module[d].append(s["id"])

        work = deque((sid, 0) for sid in start_stmts)
        if depth == 0:
            crit_defs = {d for sid in start_stmts for d in by_id[sid]["defs"]}
            if crit_defs:
                for t in stmts:
                    if t["func"] == fid and t["id"] not in start_stmts and t["id"] > min(start_stmts) and crit_defs & set(t["uses"]) and (t["end"] - t["start"]) <= 10:
                        work.append((t["id"], 1))
        seen: Set[int] = set()
        while work:
            sid, dist = work.popleft()
            if sid in seen or (budget[0] <= 0 and sid not in start_stmts):
                continue
            seen.add(sid)
            s = by_id[sid]
            compound = s["kind"] in COMPOUND_KINDS
            small_criterion = sid in start_stmts and (s["end"] - s["start"]) <= 10
            if compound and not small_criterion and sid not in fa["full"]:
                fa["header"].add(sid)
            else:
                fa["full"].add(sid)
                fa["header"].discard(sid)
                if compound:
                    for t in stmts:
                        if t["parent_stmt"] == sid:
                            fa["full"].add(t["id"])
                budget[0] -= max(1, s["end"] - s["start"] + 1)
            if s["func"] == 0 and sid in start_stmts:
                acc.setdefault("__meta__", {"full": set(), "header": set()})["full"].add(-1)
            p = s["parent_stmt"]
            while p is not None:
                if p not in fa["header"] and p not in fa["full"]:
                    fa["header"].add(p)
                    work.append((p, dist + 1))
                p = by_id[p]["parent_stmt"]
            for u in s["uses"]:
                if u in params or u in ("this", "self", "require", "module", "exports", "console"):
                    continue
                cands = [d for d in defs_in_func.get(u, []) if d < sid and d != sid]
                if not cands:
                    cands = [d for d in defs_in_func.get(u, []) if d != sid and by_id[d]["kind"] in ("function", "functiondef", "asyncfunctiondef", "class", "classdef")]
                if cands:
                    for d in cands[-3:]:
                        work.append((d, dist + 1))
                elif u in defs_in_module and fid != 0:
                    for d in defs_in_module[u][-2:]:
                        work.append((d, dist + 1))
                f = func_by_name.get(u)
                if f and dist < 2 and (f["end"] - f["start"]) <= self.small_callee_lines and f["stmt"] not in fa["full"]:
                    fa["full"].add(f["stmt"])
                    fa["header"].discard(f["stmt"])
                    for t in stmts:
                        if t["func"] == f["id"]:
                            fa["full"].add(t["id"])
                    budget[0] -= f["end"] - f["start"] + 1
        if fid != 0 and "stmt" in fdef:
            fa["header"].add(fdef["stmt"])
            pf = fdef["parent"]
            while pf not in (None, 0):
                pfd = ir["functions"][pf]
                if "stmt" in pfd:
                    fa["header"].add(pfd["stmt"])
                pf = pfd["parent"]
        if fid != 0 and depth < self.max_caller_depth and self.graph is not None:
            callers = self.graph.callers.get((file, fid), [])[: self.max_callers]
            for c in callers:
                cf, cfid, cstmt = c["file"], c["fid"], c["stmt"]
                if cf not in self.irs:
                    continue
                if cstmt is None:
                    from Codes.Detect.static.callgraph import _stmt_at_line
                    cstmt = _stmt_at_line(self.irs[cf], cfid, c["line"])
                if cstmt is None:
                    continue
                label = self.irs[cf]["functions"][cfid]["qualname"]
                if cf != file:
                    label = f"{os.path.relpath(cf, self.package_path)}:{label}"
                if label not in chain:
                    chain.append(label)
                self._backward(cf, [cstmt], depth + 1, acc, chain, budget)

    def _render(self, acc: Dict[str, Dict[str, Set[int]]], criteria_ids: Optional[Dict[str, Set[int]]] = None) -> Tuple[str, Dict[str, List[int]], bool]:
        """Render the sliced statements as code."""
        parts, lines_out = [], {}
        criteria_ids = criteria_ids or {}
        acc = {k: v for k, v in acc.items() if k != "__meta__"}
        files = sorted(acc.keys(), key=lambda f: (f != list(acc.keys())[0], f))
        for file in files:
            ir, src = self.irs[file], self.sources.get(file, [])
            by_id = {s["id"]: s for s in ir["statements"]}
            lines: Set[int] = set()
            for sid in acc[file]["full"]:
                s = by_id[sid]
                lines.update(range(s["start"], s["end"] + 1))
            for sid in acc[file]["header"]:
                s = by_id[sid]
                if s["kind"] in COMPOUND_KINDS:
                    lines.update(range(s["start"], s["header_end"] + 1))
                    lines.update(s["extra_header_lines"])
                else:
                    lines.add(s["start"])
                if ir["lang"] == "js" and s["end"] > s["start"]:
                    lines.add(s["end"])
            lines = sorted(l for l in lines if 1 <= l <= len(src))
            if len(lines) > self.max_lines * 2:
                keep = set()
                crit = {by_id[sid]["start"] for sid in acc[file]["full"] if sid in criteria_ids.get(file, set())}
                for c in crit:
                    keep.update(range(max(1, c - 15), min(len(src), c + 15) + 1))
                for sid in acc[file]["header"]:
                    h = by_id[sid]
                    if h["kind"] in COMPOUND_KINDS and h["header_end"] - h["start"] <= 5:
                        keep.update(range(h["start"], h["header_end"] + 1))
                    else:
                        keep.add(h["start"])
                    if ir["lang"] == "js" and h["end"] > h["start"]:
                        keep.add(h["end"])
                lines = sorted(keep) if keep else lines[: self.max_lines * 2]
            lines_out[file] = lines
            body = []
            prev = None
            for l in lines:
                if prev is not None and l > prev + 1:
                    body.append("    ..." if ir["lang"] == "py" else "    // ...")
                line = src[l - 1].rstrip()
                body.append(line if len(line) <= 12000 else line[:12000] + " /* ...truncated... */")
                prev = l
            if len(acc) > 1:
                parts.append(f"{'#' if ir['lang'] == 'py' else '//'} ---- file: {os.path.relpath(file, self.package_path)} ----")
            parts.append("\n".join(body))
        return "\n".join(parts), lines_out, len(acc) > 1

    def _trigger(self, file: str, acc: Dict[str, Dict[str, Set[int]]], chain: List[str], fid: int) -> str:
        """Describe when a slice runs."""
        module_level = -1 in acc.get("__meta__", {}).get("full", set())
        in_hook = any(f in self.hook_files for f in acc if f != "__meta__")
        base = os.path.basename(file)
        fname = self.irs[file]["functions"][fid]["qualname"]
        if module_level and (in_hook or base == "setup.py"):
            return "During installation (setup.py)" if self.package_manager == "pypi" else "During installation (npm lifecycle script)"
        if module_level:
            return "At import-time (module-level code)"
        where = "install-time script file" if in_hook else "module"
        if chain:
            return f"When called (reached via {' -> '.join(str(c) for c in chain)} -> {fname}; module scope not reached in {where})"
        return f"When called (function {fname}; no caller found in package)"

    def _slice_ir(self, file: str) -> List[Dict[str, Any]]:
        """Slice a parsed file."""
        ir = self.irs[file]
        criteria = self._criteria(ir)
        if not criteria:
            return []
        by_func: Dict[int, List[int]] = defaultdict(list)
        for sid in criteria:
            by_func[ir["statements"][sid]["func"]].append(sid)
        slices = []
        for fid, sids in sorted(by_func.items(), key=lambda kv: min(kv[1])):
            acc: Dict[str, Dict[str, Set[int]]] = {}
            chain: List[str] = []
            budget = [self.max_lines]
            self._backward(file, sorted(sids), 0, acc, chain, budget)
            code, lines, cross = self._render(acc, {file: set(sids)})
            apis = sorted({a for sid in sids for a, _ in criteria[sid]})
            cats = sorted({c for sid in sids for _, c in criteria[sid]})
            slices.append({
                "code": code, "sensitive_apis": apis, "categories": cats,
                "trigger": self._trigger(file, acc, chain, fid),
                "entry_chain": list(reversed(chain)), "lines": {os.path.relpath(f, self.package_path): v for f, v in lines.items()},
                "cross_file": cross, "n_lines": sum(len(v) for v in lines.values()),
                "criteria_lines": sorted(ir["statements"][sid]["start"] for sid in sids),
                "function": ir["functions"][fid]["qualname"],
            })
            if len(slices) >= self.max_slices_per_file:
                break
        keyed = [(set((f, l) for f, ls in s["lines"].items() for l in ls), s) for s in slices]
        kept = []
        for i, (ks, s) in enumerate(keyed):
            if any(j != i and ks <= kj and (ks != kj or j < i) for j, (kj, _) in enumerate(keyed)):
                continue
            kept.append(s)
        return kept

    def _slice_unparsed(self, file: str) -> List[Dict[str, Any]]:
        """Token windows for a file the parser could not handle."""
        src = self.sources.get(file, [])
        lang = "python" if file.endswith(".py") else "javascript"
        mods, mems, glob = self.apis.cat[lang]
        tokens = list(mods) + list(mems) + [g for g in glob if g not in ("require", "import")]
        pat = re.compile(r"(?<![\w$])(" + "|".join(re.escape(t) for t in tokens) + r")(?![\w$])")
        strong_ind = [p for n, p in INDICATORS if n not in WEAK_INDICATORS]
        strong_tokens = list(mems) + [g for g in glob if g not in ("require", "import")]
        pat_strong = re.compile(r"(?<![\w$])(" + "|".join(re.escape(t) for t in strong_tokens) + r")(?![\w$])")
        hits = [i + 1 for i, l in enumerate(src) if len(l) < 20000 and (pat.search(l) or any(p.search(l) for p in strong_ind))]
        slices = []
        rel = os.path.relpath(file, self.package_path)
        for i, l in enumerate(src):
            if len(l) < 20000:
                continue
            pos = sorted({m.start() for m in pat_strong.finditer(l)} | {m.start() for p in strong_ind for m in p.finditer(l)})
            wins, cur = [], None
            for q in pos:
                if cur and q - cur[1] <= 1500:
                    cur[1] = min(len(l), q + 1500)
                else:
                    cur = [max(0, q - 1500), min(len(l), q + 1500)]
                    wins.append(cur)
            for a, b in wins[:8]:
                code = l[a:b]
                slices.append({"code": code[:6000], "sensitive_apis": sorted(set(pat.findall(code))), "categories": [],
                               "trigger": "unknown (minified single-line file; character window)", "entry_chain": [],
                               "lines": {rel: [i + 1]}, "cross_file": False, "n_lines": 1, "criteria_lines": [],
                               "function": "?", "char_range": [a, b]})
        if not hits:
            return slices[: self.max_slices_per_file]
        windows, cur = [], None
        for h in hits:
            if cur and h - cur[1] <= 8:
                cur[1] = min(len(src), h + 6)
            else:
                cur = [max(1, h - 6), min(len(src), h + 6)]
                windows.append(cur)
        for a, b in windows[: self.max_slices_per_file]:
            code = "\n".join(src[a - 1:b])
            apis = sorted(set(pat.findall(code)))
            slices.append({"code": code[:6000], "sensitive_apis": apis, "categories": [],
                           "trigger": "unknown (file could not be parsed; token window)", "entry_chain": [],
                           "lines": {os.path.relpath(file, self.package_path): list(range(a, b + 1))},
                           "cross_file": False, "n_lines": b - a + 1, "criteria_lines": [], "function": "?"})
        return slices[: self.max_slices_per_file]

    def _slice_package_json(self, file: str) -> List[Dict[str, Any]]:
        """Slices for install hooks and remote dependencies in package.json."""
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as fh:
                raw = fh.read()
            data = json.loads(raw)
        except Exception:
            return []
        if not isinstance(data, dict):
            return []
        scripts = data.get("scripts", {}) or {}
        hooks = {k: v for k, v in scripts.items() if k in INSTALL_HOOKS}
        slices = []
        rel = os.path.relpath(file, self.package_path)
        src = raw.split("\n")
        if hooks:
            lines = self._json_block_lines(src, "scripts")
            lines += [i for i, l in enumerate(src, 1) if re.search(r'"(name|version)"\s*:', l) and i not in lines]
            lines = sorted(set(lines))
            compact = len(lines) <= 1 or any(len(src[i - 1]) > 300 for i in lines)
            code = (json.dumps({"name": data.get("name"), "version": data.get("version"), "scripts": hooks}, indent=2)
                    if compact or not lines else "\n".join(src[i - 1] for i in lines))
            slices.append({"code": code, "sensitive_apis": [f"npm:{k}" for k in hooks], "categories": ["process"],
                           "trigger": "During installation (npm lifecycle script)", "entry_chain": [],
                           "lines": {rel: lines}, "cross_file": False, "n_lines": len(lines) or code.count("\n") + 1,
                           "criteria_lines": [i for i, l in enumerate(src, 1) if re.search(r'"(' + "|".join(hooks) + r')"\s*:', l)],
                           "function": "package.json#scripts"})
        deps = {}
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            for k, v in (data.get(field) or {}).items():
                if isinstance(v, str) and re.match(r"^(https?://|git\+|git://|file:|ssh://|github:)", v):
                    deps[k] = v
        if deps:
            code = json.dumps({"name": data.get("name"), "dependencies": deps}, indent=2)
            slices.append({"code": code, "sensitive_apis": ["npm:remote-dependency"], "categories": ["network"],
                           "trigger": "During installation (dependency resolution)", "entry_chain": [],
                           "lines": {}, "cross_file": False, "n_lines": code.count("\n") + 1, "criteria_lines": [],
                           "function": "package.json#dependencies"})
        return slices

    @staticmethod
    def _json_block_lines(src: List[str], key: str) -> List[int]:
        """Line range of a top-level key in a pretty-printed JSON file."""
        start = next((i for i, l in enumerate(src, 1) if re.search(r'"' + re.escape(key) + r'"\s*:', l)), None)
        if start is None:
            return []
        depth, lines = 0, []
        for i in range(start, len(src) + 1):
            lines.append(i)
            depth += src[i - 1].count("{") - src[i - 1].count("}")
            if depth <= 0 and i > start:
                break
            if depth <= 0 and "{" not in src[i - 1]:
                break
        return lines

    def _slice_shell(self, file: str) -> List[Dict[str, Any]]:
        """Slice a shell script."""
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().split("\n")
        except Exception:
            return []
        pat = re.compile(r"\b(curl|wget|bash|sh\b|chmod|chown|base64|eval|python|node|nc\b|ncat|powershell|certutil|scp|ssh|Invoke-WebRequest|Invoke-Expression|iwr|iex|bitsadmin|start|cmd|del|reg|schtasks|rundll32|regsvr32|mshta)\b", re.I)
        if not any(pat.search(l) for l in lines):
            return []
        code = "\n".join(lines[:80])
        return [{"code": code, "sensitive_apis": sorted(set(pat.findall(code))), "categories": ["process"],
                 "trigger": "During installation (shell script)" if file in self.hook_files else "When executed (shell script)",
                 "entry_chain": [], "lines": {os.path.relpath(file, self.package_path): list(range(1, min(80, len(lines)) + 1))},
                 "cross_file": False, "n_lines": min(80, len(lines)), "criteria_lines": [], "function": "shell"}]

    def _summarize(self, s: Dict[str, Any]) -> str:
        """Behavior summary of a slice."""
        fallback = f"{s.get('trigger', 'When called')}, the code invokes {', '.join(s.get('sensitive_apis', [])[:6]) or 'sensitive APIs'}."
        if self.llm_agent is None:
            return fallback
        rel = os.path.relpath(s["file_path"], self.package_path) if self.package_path else s["file_path"]
        prompt = (self.summary_prompt.replace("{file}", rel).replace("{trigger}", s.get("trigger", ""))
                  .replace("{apis}", ", ".join(s.get("sensitive_apis", []))).replace("{code}", s["code"][:8000]))
        try:
            resp = self.llm_agent.perform_query([{"role": "user", "content": prompt}], extract_json=False, max_tokens=1500)
            resp = (resp or "").strip().strip('`"')
            return resp or fallback
        except Exception as e:
            logger.warning(f"behavior summary failed: {e}")
            return fallback


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Static sensitive-code slicer")
    ap.add_argument("package_path")
    ap.add_argument("-m", "--manager", choices=("npm", "pypi"), default=None)
    ap.add_argument("-o", "--output")
    ap.add_argument("--llm", action="store_true", help="generate behavior summaries with the configured LLM")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    pm = args.manager or ("pypi" if any(Path(args.package_path).rglob("*.py")) else "npm")
    agent = None
    if args.llm:
        from Codes.GPTAnalysis.llmquery import LLMAgent
        agent = LLMAgent()
    sl = StaticCodeSlicer(llm_agent=agent)
    res = sl.slice_package(args.package_path, pm)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, ensure_ascii=False)
    for fr in res["files"]:
        for s in fr["slices"]:
            print("=" * 80)
            print(f"{s['slice_id']}  [{s['trigger']}]  apis={s['sensitive_apis']}  chain={s['entry_chain']}  lines={s['n_lines']}")
            print(s["code"])
            print("--> ", s["behavior_summary"])
    print(json.dumps(res["stats"], indent=1))
