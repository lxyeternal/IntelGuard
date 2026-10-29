"""Statement-level IR of Python files."""
import ast
import json
import sys
from typing import Any, Dict, List, Optional


COMPOUND = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith,
            ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
if hasattr(ast, "TryStar"):
    COMPOUND = COMPOUND + (ast.TryStar,)
if hasattr(ast, "Match"):
    COMPOUND = COMPOUND + (ast.Match,)


def _dotted(node: ast.AST) -> Optional[str]:
    """Dotted string of a Name or Attribute chain."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = _dotted(node.func)
        if inner:
            parts.append(inner + "()")
            return ".".join(reversed(parts))
    return None


class _NameCollector(ast.NodeVisitor):
    """Collect defs, uses, calls and members of one statement."""

    def __init__(self):
        """Create empty collections."""
        self.defs, self.uses, self.calls, self.members = [], [], [], []

    def visit_Name(self, node):
        """Record a name."""
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.defs.append(node.id)
        else:
            self.uses.append(node.id)

    def visit_Attribute(self, node):
        """Record a member access."""
        d = _dotted(node)
        if d:
            self.members.append(d)
        self.generic_visit(node)

    def visit_Call(self, node):
        """Record a call."""
        d = _dotted(node.func)
        if d:
            self.calls.append(d)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """Record a nested function name without descending."""
        self.defs.append(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        """Record a class name without descending."""
        self.defs.append(node.name)

    def visit_Lambda(self, node):
        """Skip lambda bodies."""
        self.generic_visit(node)

    def visit_arg(self, node):
        """Record a parameter."""
        self.defs.append(node.arg)


def _header_nodes(node: ast.AST) -> List[ast.AST]:
    """Header sub-nodes of a compound statement."""
    if isinstance(node, ast.If) or isinstance(node, ast.While):
        return [node.test]
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return [node.target, node.iter]
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return [i for item in node.items for i in (item.context_expr, item.optional_vars) if i is not None]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return [node.args] + list(node.decorator_list)
    if isinstance(node, ast.ClassDef):
        return list(node.bases) + list(node.decorator_list)
    if isinstance(node, ast.Try) or (hasattr(ast, "TryStar") and isinstance(node, ast.TryStar)):
        return [h.type for h in node.handlers if h.type is not None]
    if hasattr(ast, "Match") and isinstance(node, ast.Match):
        return [node.subject]
    return []


def _body_lists(node: ast.AST):
    """Statement lists of a compound statement."""
    out = []
    for field in ("body", "orelse", "finalbody"):
        v = getattr(node, field, None)
        if isinstance(v, list) and v and isinstance(v[0], ast.stmt):
            out.append(v)
    if hasattr(node, "handlers"):
        for h in node.handlers:
            out.append(h.body)
    if hasattr(node, "cases"):
        for c in node.cases:
            out.append(c.body)
    return out


def _header_end(node: ast.AST) -> int:
    """Last line of a statement header."""
    bodies = _body_lists(node)
    first = min((b[0].lineno for b in bodies if b), default=node.lineno)
    return max(node.lineno, first - 1) if first > node.lineno else node.lineno


def _extra_header_lines(node: ast.AST) -> List[int]:
    """Lines of else, except and similar secondary headers."""
    lines = []
    if hasattr(node, "handlers"):
        lines += [h.lineno for h in node.handlers]
    for field in ("orelse", "finalbody"):
        v = getattr(node, field, None)
        if isinstance(v, list) and v:
            if isinstance(node, ast.If) and len(v) == 1 and isinstance(v[0], ast.If) and v[0].col_offset == node.col_offset:
                continue
            lines.append(v[0].lineno - 1)
    if hasattr(node, "cases"):
        lines += [c.pattern.lineno for c in node.cases]
    return lines


def build_ir(path: str, source: Optional[str] = None) -> Dict[str, Any]:
    """Build the IR of one file."""
    if source is None:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    ir: Dict[str, Any] = {"file": path, "lang": "py", "parse_ok": True, "error": None,
                          "n_lines": source.count("\n") + 1, "functions": [], "statements": []}
    try:
        tree = ast.parse(source)
    except Exception as e:
        ir["parse_ok"], ir["error"] = False, str(e)
        ir["functions"] = [{"id": 0, "name": "<module>", "qualname": "<module>", "start": 1,
                            "end": ir["n_lines"], "parent": None, "params": []}]
        return ir

    functions = [{"id": 0, "name": "<module>", "qualname": "<module>", "start": 1,
                  "end": ir["n_lines"], "parent": None, "params": []}]
    statements: List[Dict[str, Any]] = []

    def walk(stmts: List[ast.stmt], func_id: int, parent_stmt: Optional[int], qual_prefix: str):
        """Walk a statement list."""
        for node in stmts:
            sid = len(statements)
            kind = type(node).__name__.lower()
            col = _NameCollector()
            if isinstance(node, COMPOUND):
                for h in _header_nodes(node):
                    col.visit(h)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    col.defs.append(node.name)
            else:
                col.visit(node)
            imports = {}
            if isinstance(node, ast.Import):
                for a in node.names:
                    alias = a.asname or a.name.split(".")[0]
                    imports[alias] = a.name
                    col.defs.append(alias)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    alias = a.asname or a.name
                    imports[alias] = f"{mod}.{a.name}" if mod else a.name
                    col.defs.append(alias)
            stmt = {
                "id": sid, "func": func_id, "start": node.lineno,
                "end": getattr(node, "end_lineno", node.lineno),
                "header_end": _header_end(node) if isinstance(node, COMPOUND) else getattr(node, "end_lineno", node.lineno),
                "extra_header_lines": _extra_header_lines(node) if isinstance(node, COMPOUND) else [],
                "kind": kind, "parent_stmt": parent_stmt,
                "defs": sorted(set(col.defs)), "uses": sorted(set(col.uses)),
                "calls": sorted(set(col.calls)), "members": sorted(set(col.members)),
                "imports": imports,
            }
            statements.append(stmt)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fid = len(functions)
                qual = f"{qual_prefix}.{node.name}" if qual_prefix else node.name
                functions.append({"id": fid, "name": node.name, "qualname": qual, "start": node.lineno,
                                  "end": getattr(node, "end_lineno", node.lineno), "parent": func_id,
                                  "params": [a.arg for a in node.args.args + node.args.kwonlyargs]
                                            + ([node.args.vararg.arg] if node.args.vararg else [])
                                            + ([node.args.kwarg.arg] if node.args.kwarg else []),
                                  "stmt": sid})
                stmt["func_def"] = fid
                walk(node.body, fid, sid, qual)
            elif isinstance(node, ast.ClassDef):
                qual = f"{qual_prefix}.{node.name}" if qual_prefix else node.name
                for b in _body_lists(node):
                    walk(b, func_id, sid, qual)
            elif isinstance(node, COMPOUND):
                for b in _body_lists(node):
                    walk(b, func_id, sid, qual_prefix)

    walk(tree.body, 0, None, "")
    ir["functions"], ir["statements"] = functions, statements
    return ir


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(json.dumps(build_ir(p), indent=1))
