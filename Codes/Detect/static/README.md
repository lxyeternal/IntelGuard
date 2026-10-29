# Static sensitive-code slicing

Slices the code of a package that reaches sensitive APIs, so that detection
judges only the relevant parts of each file.

## Pipeline

```
package dir
  ├─ py_ir.py / js_ir.js     statement-level IR per file (defs / uses / calls / members / imports)
  ├─ callgraph.py            Jelly (npm) or PyCG (PyPI) call graph, merged with an IR name resolver
  └─ static_slice.py         criteria = sensitive API call sites (sensitive_apis.json) and suspicious
                             data indicators; backward data-flow and control-flow slice inside the
                             function, extended to callers through the call graph; one slice per
                             function, behavior summary by the LLM (behavior_summary_prompt.txt)
```

Each slice carries `sensitive_apis`, `categories`, `trigger`, `entry_chain`, `lines`,
`cross_file`, `criteria_lines` and `function`. Install hooks and remote dependencies in
`package.json` and shell scripts run by hooks become slices as well. Files the parser cannot
handle fall back to windows around sensitive tokens.

## Usage

```bash
# slice one package and print the slices (add --llm for behavior summaries)
python Codes/Detect/static/static_slice.py <pkg_dir> -m npm|pypi

# detect one package
python Codes/Detect/run_detection.py <pkg_dir> -m npm|pypi

# batch detection over a dataset laid out as unzip_<label>/<pkg>/<version>/
python Codes/Detect/run_npm_dataset.py --dataset-root <dir> --output-root <dir> --limit 0

# tests
python -m pytest Codes/Detect/static/tests -q
```

External tools: `jelly` on PATH (`npm i -g @cs-au-dk/jelly`) and `pycg` (override with `PYCG_BIN`).
