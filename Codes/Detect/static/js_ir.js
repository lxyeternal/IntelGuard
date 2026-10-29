// Statement-level IR of JavaScript files, built with @babel/parser.
const fs = require("fs");
const path = require("path");

// Load @babel/parser from the local or the global jelly node_modules.
function loadParser() {
  const candidates = [
    "@babel/parser",
    "/usr/lib/node_modules/@cs-au-dk/jelly/node_modules/@babel/parser",
    path.join(process.env.JELLY_HOME || "", "node_modules/@babel/parser"),
  ];
  for (const c of candidates) {
    try { return require(c); } catch (e) {}
  }
  throw new Error("@babel/parser not found; set JELLY_HOME or npm install @babel/parser");
}
const parser = loadParser();

const COMPOUND = new Set([
  "IfStatement", "ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement",
  "DoWhileStatement", "TryStatement", "SwitchStatement", "FunctionDeclaration",
  "ClassDeclaration", "BlockStatement", "LabeledStatement", "WithStatement",
]);
const FUNC_TYPES = new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ObjectMethod", "ClassMethod", "ClassPrivateMethod"]);

// Dotted string of an identifier or member chain.
function dotted(node) {
  const parts = [];
  let n = node;
  while (n && (n.type === "MemberExpression" || n.type === "OptionalMemberExpression")) {
    if (n.property.type === "Identifier" && !n.computed) parts.push(n.property.name);
    else if (n.property.type === "StringLiteral") parts.push(n.property.value);
    else parts.push("[]");
    n = n.object;
  }
  if (!n) return null;
  if (n.type === "Identifier") { parts.push(n.name); return parts.reverse().join("."); }
  if (n.type === "ThisExpression") { parts.push("this"); return parts.reverse().join("."); }
  if (n.type === "CallExpression" || n.type === "OptionalCallExpression" || n.type === "NewExpression") {
    const inner = dotted(n.callee);
    if (inner) {
      let base = inner + "()";
      if (inner === "require" && n.arguments.length && n.arguments[0].type === "StringLiteral")
        base = `require('${n.arguments[0].value}')`;
      parts.push(base);
      return parts.reverse().join(".");
    }
  }
  if (n.type === "StringLiteral") { parts.push(JSON.stringify(n.value)); return parts.reverse().join("."); }
  return null;
}

// Names bound by a destructuring pattern.
function patternNames(p, out) {
  if (!p) return;
  switch (p.type) {
    case "Identifier": out.push(p.name); break;
    case "ObjectPattern": for (const pr of p.properties) patternNames(pr.value || pr.argument, out); break;
    case "ArrayPattern": for (const el of p.elements) patternNames(el, out); break;
    case "RestElement": patternNames(p.argument, out); break;
    case "AssignmentPattern": patternNames(p.left, out); break;
    default: break;
  }
}

// Collect defs, uses, calls, members and imports of one statement.
function collect(node, acc, skipNested) {
  if (!node || typeof node.type !== "string") return;
  if (skipNested && FUNC_TYPES.has(node.type)) {
    if (node.id && node.id.name) acc.defs.push(node.id.name);
    return;
  }
  switch (node.type) {
    case "Identifier": acc.uses.push(node.name); return;
    case "ThisExpression": acc.uses.push("this"); return;
    case "MemberExpression": case "OptionalMemberExpression": {
      const d = dotted(node); if (d) acc.members.push(d);
      collect(node.object, acc, skipNested);
      if (node.computed) collect(node.property, acc, skipNested);
      return;
    }
    case "CallExpression": case "OptionalCallExpression": case "NewExpression": {
      const d = dotted(node.callee); if (d) acc.calls.push(d);
      if (d === "require" && node.arguments.length && node.arguments[0].type === "StringLiteral")
        acc.calls.push(`require('${node.arguments[0].value}')`);
      collect(node.callee, acc, skipNested);
      for (const a of node.arguments) collect(a, acc, skipNested);
      return;
    }
    case "Import": acc.calls.push("import"); return;
    case "VariableDeclarator": {
      const names = []; patternNames(node.id, names); acc.defs.push(...names);
      if (node.init) {
        const c = node.init;
        const req = (c.type === "CallExpression" && c.callee.type === "Identifier" && c.callee.name === "require"
                     && c.arguments.length && c.arguments[0].type === "StringLiteral") ? c.arguments[0].value : null;
        if (req) {
          if (node.id.type === "Identifier") acc.imports[node.id.name] = req;
          else if (node.id.type === "ObjectPattern")
            for (const pr of node.id.properties) if (pr.key && pr.value && pr.value.type === "Identifier")
              acc.imports[pr.value.name] = req + "." + (pr.key.name || pr.key.value);
        }
        if (c.type === "MemberExpression" && c.object.type === "CallExpression" && c.object.callee.type === "Identifier"
            && c.object.callee.name === "require" && c.object.arguments.length && c.object.arguments[0].type === "StringLiteral"
            && node.id.type === "Identifier" && c.property.type === "Identifier")
          acc.imports[node.id.name] = c.object.arguments[0].value + "." + c.property.name;
        collect(node.init, acc, skipNested);
      }
      return;
    }
    case "AssignmentExpression": {
      if (node.left.type === "Identifier") acc.defs.push(node.left.name);
      else if (node.left.type === "MemberExpression") { const d = dotted(node.left); if (d) acc.members.push(d); collect(node.left.object, acc, skipNested); }
      else { const names = []; patternNames(node.left, names); acc.defs.push(...names); }
      collect(node.right, acc, skipNested);
      return;
    }
    case "UpdateExpression": collect(node.argument, acc, skipNested); if (node.argument.type === "Identifier") acc.defs.push(node.argument.name); return;
    case "ImportDeclaration": {
      for (const s of node.specifiers) {
        acc.defs.push(s.local.name);
        if (s.type === "ImportDefaultSpecifier" || s.type === "ImportNamespaceSpecifier") acc.imports[s.local.name] = node.source.value;
        else acc.imports[s.local.name] = node.source.value + "." + (s.imported.name || s.imported.value);
      }
      return;
    }
    case "FunctionDeclaration": case "ClassDeclaration": if (node.id) acc.defs.push(node.id.name); return;
    case "ObjectProperty": case "ObjectMethod": { if (node.computed) collect(node.key, acc, skipNested); collect(node.value, acc, skipNested); return; }
    case "StringLiteral": case "NumericLiteral": case "BooleanLiteral": case "NullLiteral": case "RegExpLiteral": case "TemplateElement": return;
    default: break;
  }
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "start" || key === "end" || key === "leadingComments" || key === "trailingComments" || key === "innerComments" || key === "extra") continue;
    const v = node[key];
    if (Array.isArray(v)) { for (const x of v) if (x && typeof x.type === "string") collect(x, acc, skipNested); }
    else if (v && typeof v.type === "string") collect(v, acc, skipNested);
  }
}

// Header sub-nodes of a compound statement.
function headerParts(node) {
  switch (node.type) {
    case "IfStatement": case "WhileStatement": case "DoWhileStatement": case "SwitchStatement": return [node.test || node.discriminant];
    case "ForStatement": return [node.init, node.test, node.update];
    case "ForInStatement": case "ForOfStatement": return [node.left, node.right];
    case "WithStatement": return [node.object];
    case "FunctionDeclaration": return node.params;
    case "ClassDeclaration": return [node.superClass];
    case "TryStatement": return node.handler ? [node.handler.param] : [];
    default: return [];
  }
}

// Statement lists of a compound statement.
function bodyLists(node) {
  const out = [];
  const push = (b) => { if (!b) return; if (b.type === "BlockStatement") out.push(b.body); else out.push([b]); };
  switch (node.type) {
    case "IfStatement": push(node.consequent); push(node.alternate); break;
    case "ForStatement": case "ForInStatement": case "ForOfStatement": case "WhileStatement": case "DoWhileStatement": case "WithStatement": case "LabeledStatement": push(node.body); break;
    case "TryStatement": push(node.block); if (node.handler) push(node.handler.body); push(node.finalizer); break;
    case "SwitchStatement": for (const c of node.cases) out.push(c.consequent); break;
    case "BlockStatement": out.push(node.body); break;
    case "FunctionDeclaration": push(node.body); break;
    case "ClassDeclaration": out.push(node.body.body); break;
    default: break;
  }
  return out;
}

// Build the IR of one file.
function buildIR(file) {
  const src = fs.readFileSync(file, "utf8");
  const ir = { file, lang: "js", parse_ok: true, error: null, n_lines: src.split("\n").length, functions: [], statements: [] };
  let ast;
  try {
    ast = parser.parse(src, { sourceType: "unambiguous", errorRecovery: true, allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true, allowImportExportEverywhere: true, allowUndeclaredExports: true,
      plugins: ["jsx", "typescript", "decorators-legacy", "classProperties", "dynamicImport", "optionalChaining", "nullishCoalescingOperator", "topLevelAwait"] });
  } catch (e) {
    ir.parse_ok = false; ir.error = String(e.message || e);
    ir.functions.push({ id: 0, name: "<module>", qualname: "<module>", start: 1, end: ir.n_lines, parent: null, params: [] });
    return ir;
  }
  const functions = [{ id: 0, name: "<module>", qualname: "<module>", start: 1, end: ir.n_lines, parent: null, params: [] }];
  const statements = [];

  // Register a function node and return its id.
  function registerFunction(fnode, name, parentFunc, parentStmt, qualPrefix, role) {
    const fid = functions.length;
    const qual = qualPrefix ? qualPrefix + "." + name : name;
    const params = []; for (const p of fnode.params || []) patternNames(p, params);
    functions.push({ id: fid, name, qualname: qual, start: fnode.loc.start.line, end: fnode.loc.end.line, parent: parentFunc, params, stmt: parentStmt, role: role || "declaration" });
    if (fnode.body && fnode.body.type === "BlockStatement") walk(fnode.body.body, fid, parentStmt, qual);
    else if (fnode.body) {
      walkExpressionAsStatement(fnode.body, fid, parentStmt, qual);
    }
    return fid;
  }

  // Function expressions nested in a statement with their syntactic role.
  function findNestedFunctions(node, out, depth, parent, key) {
    if (!node || typeof node.type !== "string" || depth > 60) return;
    if (FUNC_TYPES.has(node.type) && node.type !== "FunctionDeclaration") { out.push({ fn: node, parent, key }); return; }
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "extra") continue;
      const v = node[k];
      if (Array.isArray(v)) { for (const x of v) if (x && typeof x.type === "string") findNestedFunctions(x, out, depth + 1, node, k); }
      else if (v && typeof v.type === "string") findNestedFunctions(v, out, depth + 1, node, k);
    }
  }

  // Describe how a nested function gets invoked.
  function nestedInfo(entry) {
    const fnode = entry.fn, parent = entry.parent, key = entry.key;
    let name = null, role = "other";
    if (fnode.id && fnode.id.name) name = fnode.id.name;
    if (fnode.key && (fnode.key.name || fnode.key.value)) { name = name || fnode.key.name || fnode.key.value; role = "method"; }
    if (parent) {
      if (parent.type === "VariableDeclarator" && key === "init") { name = name || (parent.id.type === "Identifier" ? parent.id.name : null); role = "assigned"; }
      else if (parent.type === "AssignmentExpression" && key === "right") {
        const d = dotted(parent.left) || ""; name = name || d.split(".").pop() || null;
        role = /^(module\.exports|exports)\b/.test(d) ? "exported" : "assigned";
      }
      else if ((parent.type === "ObjectProperty" || parent.type === "ClassProperty") && key === "value") { name = name || (parent.key && (parent.key.name || parent.key.value)) || null; role = "property"; }
      else if ((parent.type === "CallExpression" || parent.type === "NewExpression" || parent.type === "OptionalCallExpression") && key === "arguments") role = "callarg";
      else if ((parent.type === "CallExpression" || parent.type === "OptionalCallExpression") && key === "callee") role = "iife";
      else if (parent.type === "ExportDefaultDeclaration" || parent.type === "ExportNamedDeclaration") role = "exported";
      else if (parent.type === "ReturnStatement") role = "returned";
    }
    return { name: name || ("<anon@" + fnode.loc.start.line + ">"), role };
  }

  // Record an expression as a statement.
  function walkExpressionAsStatement(expr, funcId, parentStmt, qual) {
    const sid = statements.length;
    const acc = { defs: [], uses: [], calls: [], members: [], imports: {} };
    collect(expr, acc, true);
    statements.push({ id: sid, func: funcId, start: expr.loc.start.line, end: expr.loc.end.line, header_end: expr.loc.end.line,
      extra_header_lines: [], kind: "expression", parent_stmt: parentStmt, defs: uniq(acc.defs), uses: uniq(acc.uses),
      calls: uniq(acc.calls), members: uniq(acc.members), imports: acc.imports });
    const nested = []; findNestedFunctions(expr, nested, 0, null, null);
    for (const e of nested) { const info = nestedInfo(e); registerFunction(e.fn, info.name, funcId, sid, qual, info.role); }
  }

  // Walk a statement list.
  function walk(stmts, funcId, parentStmt, qualPrefix) {
    for (let node of stmts) {
      if (!node || !node.loc) continue;
      if ((node.type === "ExportNamedDeclaration" || node.type === "ExportDefaultDeclaration") && node.declaration && node.declaration.type) {
        const inner = node.declaration;
        if (inner.type === "FunctionDeclaration" || inner.type === "ClassDeclaration" || inner.type === "VariableDeclaration") {
          inner.loc = inner.loc || node.loc; inner.__exported = true; node = inner;
        }
      }
      const sid = statements.length;
      const acc = { defs: [], uses: [], calls: [], members: [], imports: {} };
      const isCompound = COMPOUND.has(node.type);
      if (isCompound) { for (const h of headerParts(node)) if (h) collect(h, acc, true); if (node.id) acc.defs.push(node.id.name); }
      else collect(node, acc, true);
      let headerEnd = node.loc.end.line;
      const bodies = isCompound ? bodyLists(node) : [];
      if (isCompound) {
        const first = Math.min(...bodies.filter(b => b.length).map(b => b[0].loc.start.line), Infinity);
        headerEnd = first === Infinity ? node.loc.start.line : Math.max(node.loc.start.line, Math.min(first, node.loc.start.line));
      }
      const extra = [];
      if (node.type === "TryStatement") { if (node.handler) extra.push(node.handler.loc.start.line); if (node.finalizer) extra.push(node.finalizer.loc.start.line); }
      if (node.type === "IfStatement" && node.alternate) extra.push(node.alternate.loc.start.line);
      if (node.type === "SwitchStatement") for (const c of node.cases) extra.push(c.loc.start.line);
      const stmt = { id: sid, func: funcId, start: node.loc.start.line, end: node.loc.end.line, header_end: headerEnd,
        extra_header_lines: extra, kind: node.type.replace(/Statement|Declaration/, "").toLowerCase(), parent_stmt: parentStmt,
        defs: uniq(acc.defs), uses: uniq(acc.uses), calls: uniq(acc.calls), members: uniq(acc.members), imports: acc.imports };
      statements.push(stmt);
      if (node.type === "FunctionDeclaration") {
        const fid = registerFunction(node, node.id ? node.id.name : "<anon>", funcId, sid, qualPrefix, node.__exported ? "exported" : "declaration");
        stmt.func_def = fid;
      } else if (node.type === "ClassDeclaration") {
        const qual = qualPrefix ? qualPrefix + "." + (node.id ? node.id.name : "class") : (node.id ? node.id.name : "class");
        for (const m of node.body.body) if (FUNC_TYPES.has(m.type)) registerFunction(m, nestedInfo({ fn: m, parent: null, key: null }).name, funcId, sid, qual, "method");
      } else if (isCompound) {
        for (const b of bodies) walk(b, funcId, sid, qualPrefix);
        const nestedH = []; for (const h of headerParts(node)) if (h) findNestedFunctions(h, nestedH, 0, node, "header");
        for (const e of nestedH) { const info = nestedInfo(e); registerFunction(e.fn, info.name, funcId, sid, qualPrefix, info.role); }
      } else {
        const nested = []; findNestedFunctions(node, nested, 0, null, null);
        for (const e of nested) { const info = nestedInfo(e); if (node.__exported) info.role = "exported"; registerFunction(e.fn, info.name, funcId, sid, qualPrefix, info.role); }
      }
    }
  }
  walk(ast.program.body, 0, null, "");
  ir.functions = functions; ir.statements = statements;
  return ir;
}

// Sorted unique values.
function uniq(a) { return Array.from(new Set(a)).sort(); }

const files = process.argv.slice(2);
const out = [];
for (const f of files) {
  try { out.push(buildIR(f)); }
  catch (e) { out.push({ file: f, lang: "js", parse_ok: false, error: String(e.message || e), n_lines: 0, functions: [{ id: 0, name: "<module>", qualname: "<module>", start: 1, end: 1, parent: null, params: [] }], statements: [] }); }
}
process.stdout.write(JSON.stringify(out));
