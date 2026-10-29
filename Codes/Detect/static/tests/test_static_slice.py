"""Tests of the static slicer on small synthetic packages."""
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from Codes.Detect.static.static_slice import StaticCodeSlicer


def run(tmp_path: Path, files: dict, pm: str):
    """Write the files and slice the package."""
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    sl = StaticCodeSlicer(llm_agent=None, callgraph_timeout=60)
    res = sl.slice_package(str(tmp_path), pm)
    return sl, res, [s for fr in res["files"] for s in fr["slices"]]


def L(s, rel):
    """Line numbers of a slice in a file."""
    return set(s["lines"].get(rel, []))


def test_py_setup_dataflow_alias_and_module_chain(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"setup.py": '''
        from setuptools import setup
        import os
        import subprocess as sp

        def banner():
            user = os.environ.get("USER", "nobody")
            return "hello " + user

        def announce(msg):
            prefix = "[setup]"
            text = prefix + " " + msg
            sp.run(["echo", text])

        if os.name != "nt":
            announce(banner())

        setup(name="x", version="1.0")
    '''}
    _, _, slices = run(tmp_path, files, "pypi")
    s = [x for x in slices if any(a.startswith("subprocess.run") for a in x["sensitive_apis"])]
    assert s, [x["sensitive_apis"] for x in slices]
    ls = L(s[0], "setup.py")
    assert {9, 10, 11, 12}.issubset(ls), ("def + data deps prefix/text + criterion", ls)
    assert 3 in ls, "alias import must be included"
    assert {14, 15}.issubset(ls), ("module-level call site and its if header", ls)
    assert s[0]["trigger"].startswith("During installation"), s[0]["trigger"]
    assert any("<module>" in c for c in s[0]["entry_chain"]), s[0]["entry_chain"]


def test_py_control_headers_and_with_body(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {
        "pkg/__init__.py": "from .main import run\n",
        "pkg/main.py": '''
            import os
            import requests

            def run():
                try:
                    if os.environ.get("CHECK"):
                        r = requests.get("http://localhost:8000/health")
                        with open("/tmp/health.txt", "w") as f:
                            f.write(r.text)
                except Exception:
                    pass
        ''',
    }
    _, _, slices = run(tmp_path, files, "pypi")
    main = [s for s in slices if s["file_path"].endswith("main.py")]
    assert len(main) == 1, [s["slice_id"] for s in slices]
    ls = L(main[0], "pkg/main.py")
    assert {4, 5, 6, 7, 8, 9}.issubset(ls), ls
    assert "requests.get" in main[0]["sensitive_apis"] and "open" in main[0]["sensitive_apis"]
    assert main[0]["trigger"].startswith("When called"), main[0]["trigger"]


def test_py_benign_no_slices(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.py": '''
        import json

        def add(a, b):
            return json.dumps({"r": a + b})

        print(add(1, 2))
    '''}
    _, _, slices = run(tmp_path, files, "pypi")
    assert slices == []


def test_py_module_level_encoding_chain(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.py": '''
        import base64
        text = "aGVsbG8="
        raw = base64.b64decode(text)
        print(raw)
    '''}
    _, _, slices = run(tmp_path, files, "pypi")
    assert len(slices) == 1
    assert L(slices[0], "m.py") == {1, 2, 3, 4}
    assert slices[0]["trigger"].startswith("At import-time")


def test_py_class_method_reached_via_main(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.py": '''
        import subprocess

        class Runner:
            def go(self, cmd):
                return subprocess.check_output(cmd)

        def main():
            r = Runner()
            r.go(["echo", "hi"])

        main()
    '''}
    _, _, slices = run(tmp_path, files, "pypi")
    s = [x for x in slices if "subprocess.check_output" in x["sensitive_apis"]][0]
    ls = L(s, "m.py")
    assert {3, 4, 5}.issubset(ls), ls
    assert 9 in ls and 11 in ls, ("call chain main() -> go() must be included", ls)
    assert s["trigger"].startswith("At import-time"), s["trigger"]


def test_py_helper_defined_after_use_is_included(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.py": '''
        import platform

        def report():
            info = describe()
            print(platform.system(), info)

        def describe():
            return "x"

        report()
    '''}
    _, _, slices = run(tmp_path, files, "pypi")
    ls = L(slices[0], "m.py")
    assert {7, 8}.issubset(ls), ("helper defined later must still be pulled in", ls)


def test_py_cross_file_chain(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"a.py": "from b import helper\n\ndef entry():\n    helper()\n\nentry()\n",
             "b.py": "import os\n\ndef helper():\n    return os.environ.get('HOME')\n"}
    sl, _, slices = run(tmp_path, files, "pypi")
    assert sl.graph.n_edges() >= 1
    s = slices[0]
    assert s["cross_file"], "slice must extend from b.helper to the call site in a.py"
    assert 4 in L(s, "a.py") and 6 in L(s, "a.py")


JS_PKG = {
    "package.json": '{"name": "demo", "version": "1.0.0", "scripts": {"preinstall": "node index.js"}}\n',
    "index.js": '''
        const fs = require("fs");
        const https = require("https");
        const cfg = JSON.parse(fs.readFileSync("./config.json", "utf8"));

        function report(payload) {
            const host = "localhost";
            const opts = { host: host, port: 8443, path: "/report", method: "POST" };
            const req = https.request(opts, (res) => {
                res.on("data", (d) => process.stdout.write(d));
            });
            req.write(payload);
            req.end();
        }

        report(JSON.stringify({ name: cfg.name }));
    ''',
}


def test_js_hook_file_dataflow_and_module_chain(tmp_path):
    """Slicer behaviour on a synthetic package."""
    sl, _, slices = run(tmp_path, JS_PKG, "npm")
    assert any(j.startswith("jelly") for j in sl.graph.providers), sl.graph.providers
    pj = [s for s in slices if s["function"] == "package.json#scripts"]
    assert pj and pj[0]["trigger"].startswith("During installation")
    s = [x for x in slices if "https.request" in x["sensitive_apis"]]
    assert s, [x["sensitive_apis"] for x in slices]
    ls = L(s[0], "index.js")
    assert {5, 6, 7, 8}.issubset(ls), ("function header, host/opts data deps, criterion", ls)
    assert 2 in ls, "require('https') alias must be included"
    assert 15 in ls, ("module-level call site report(...)", ls)
    assert s[0]["trigger"].startswith("During installation"), s[0]["trigger"]
    assert s[0]["cross_file"] is False


def test_js_destructured_and_inline_require(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"a.js": '''
        const { execSync } = require("child_process");
        const name = require("os").hostname();
        const out = execSync("echo " + name).toString();
        console.log(out);
    '''}
    _, _, slices = run(tmp_path, files, "npm")
    assert len(slices) == 1
    apis = slices[0]["sensitive_apis"]
    assert "child_process.execSync" in apis and "os.hostname" in apis, apis
    assert L(slices[0], "a.js") == {1, 2, 3, 4}
    assert slices[0]["trigger"].startswith("At import-time")


def test_js_esm_export_function_is_walked(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.mjs": '''
        import fs from "fs";

        export function readConfig(p) {
            const full = p + "/config.json";
            return fs.readFileSync(full, "utf8");
        }
    '''}
    _, _, slices = run(tmp_path, files, "npm")
    assert len(slices) == 1, [s["slice_id"] for s in slices]
    assert "fs.readFileSync" in slices[0]["sensitive_apis"]
    assert {3, 4, 5}.issubset(L(slices[0], "m.mjs"))
    assert slices[0]["trigger"].startswith("When called")


def test_js_callback_at_module_level_counts_as_import_time(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.js": '''
        const fs = require("fs");
        setTimeout(() => {
            const txt = fs.readFileSync("./x.txt", "utf8");
            console.log(txt);
        }, 10);
    '''}
    _, _, slices = run(tmp_path, files, "npm")
    assert len(slices) == 1
    assert slices[0]["trigger"].startswith("At import-time"), slices[0]["trigger"]
    assert {2, 3}.issubset(L(slices[0], "m.js"))


def test_js_exported_function_is_not_import_time(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.js": '''
        const os = require("os");
        module.exports = function () {
            return os.platform();
        };
    '''}
    _, _, slices = run(tmp_path, files, "npm")
    assert len(slices) == 1
    assert slices[0]["trigger"].startswith("When called"), slices[0]["trigger"]


def test_js_hoisted_function_called_before_definition(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"m.js": '''
        const os = require("os");
        main();
        function main() {
            console.log(os.homedir());
        }
    '''}
    _, _, slices = run(tmp_path, files, "npm")
    assert len(slices) == 1
    ls = L(slices[0], "m.js")
    assert {2, 3, 4}.issubset(ls), ls
    assert slices[0]["trigger"].startswith("At import-time"), slices[0]["trigger"]


def test_js_cross_file_require_chain(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {
        "index.js": 'const lib = require("./lib");\nlib.check("a");\n',
        "lib.js": '''
            const fs = require("fs");
            function check(name) {
                return fs.existsSync(name);
            }
            module.exports = { check };
        ''',
    }
    _, _, slices = run(tmp_path, files, "npm")
    s = [x for x in slices if "fs.existsSync" in x["sensitive_apis"]]
    assert s and s[0]["cross_file"], [(x["sensitive_apis"], x["cross_file"]) for x in slices]
    assert 2 in L(s[0], "index.js"), s[0]["lines"]
    assert s[0]["trigger"].startswith("At import-time"), s[0]["trigger"]


def test_js_package_json_remote_dependency(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"package.json": '{"name": "d", "dependencies": {"x": "git+https://example.com/x.git"}}\n'}
    _, _, slices = run(tmp_path, files, "npm")
    assert [s["function"] for s in slices] == ["package.json#dependencies"]


def test_js_benign_no_slices(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"a.js": "function add(a, b) { return a + b; }\nmodule.exports = { add };\n"}
    _, _, slices = run(tmp_path, files, "npm")
    assert slices == []


def test_js_unparsable_file_falls_back_to_windows(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"a.js": "var x = ;;; function (\nconst cp = require('child_process');\ncp.exec('echo 1'\n"}
    sl, _, slices = run(tmp_path, files, "npm")
    assert slices and slices[0]["trigger"].startswith("unknown"), slices
    assert any("child_process" in a for a in slices[0]["sensitive_apis"])


def test_js_dedupe_subset_slices(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = {"a.js": '''
        const os = require("os");
        function a() { return os.hostname(); }
        function b() { return a() + os.platform(); }
        console.log(b());
    '''}
    _, _, slices = run(tmp_path, files, "npm")
    assert len(slices) == 1, [(s["function"], s["lines"]) for s in slices]


def test_invariants_every_slice(tmp_path):
    """Slicer behaviour on a synthetic package."""
    files = dict(JS_PKG)
    files["util.js"] = 'const os = require("os");\nfunction who() { return os.userInfo().username; }\nmodule.exports = who;\n'
    sl, _, slices = run(tmp_path, files, "npm")
    for s in slices:
        rel = Path(s["file_path"]).relative_to(tmp_path).as_posix()
        if s["lines"]:
            assert set(s["criteria_lines"]).issubset(L(s, rel)), (s["slice_id"], s["criteria_lines"], s["lines"])
        assert s["n_lines"] <= sl.max_lines * 2
        assert s["code"].strip() and s["behavior_summary"]
