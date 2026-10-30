# IntelGuard

Knowledge-driven detection of malicious npm and PyPI packages.

This repository contains the code, intelligence dataset, knowledge base and
experiment scripts of the paper:

> **Bridging Expert Reasoning and LLM Detection: A Knowledge-Driven Framework for Malicious Packages**
> Wenbo Guo, Shiwen Song, Jiaxun Guo, Zhengzi Xu, Chengwei Liu, Haoran Ou, Mengmeng Ge, Yang Liu.
> *Proceedings of the ACM Web Conference 2026 (WWW '26)*, pages 3554–3565.
> [https://doi.org/10.1145/3774904.3792083](https://doi.org/10.1145/3774904.3792083)

IntelGuard turns public security reports about malicious packages into a
structured knowledge base of expert reasoning, and uses that knowledge to
guide an LLM when judging unknown packages.

## Overview

```
security reports ──► LLM extraction ──► verify.json ──► knowledge base ──► detection
   (22 sources)      (related / extract      (per report)   (snippets, embeddings,   (slicing, retrieval,
                      / verify)                              behavior clusters)       LLM judgment)
```

1. **Intelligence collection.** Articles from security vendors, blogs and
   advisories are crawled and stored as text and images under `Dataset/Content`
   and `Dataset/Image`.
2. **Knowledge extraction.** A three-stage LLM pipeline decides whether an
   article describes a malicious package, extracts the package, its malicious
   code snippets, behaviors and attack chain, and verifies the result. The
   output of each report is a `verify.json` under `Dataset/IntelliJson`.
3. **Knowledge base.** Every snippet is stored with its code and behavior
   embeddings. Snippets are clustered at the code level and the behavior level
   with HDBSCAN, and each behavior cluster carries a unified explanation.
4. **Detection.** A target package is sliced statically: sensitive API call
   sites and suspicious data indicators are the slicing criteria, and each slice
   is the backward data-flow and control-flow slice extended to its callers
   through the package call graph (Jelly for JavaScript, PyCG for Python). Each
   slice is summarised, matched against the knowledge base by code and
   behavior similarity anchored on the behavior clusters, and judged by the LLM
   together with the retrieved expert reasoning.

## Repository layout

```
Codes/
  Collection/      crawlers for the intelligence sources
  GPTAnalysis/     LLM pipeline (related -> extract -> verify) and the LLM client
  IntelliSource/   source discovery and cross-referencing
  Keywords/        text cleaning, deduplication and topic clustering
  KnowledgeBase/   knowledge base construction, clustering and retrieval
  Detect/          static slicing and package detection
  Experiment/      scripts of the paper experiments (RQ1, RQ2)
  Dataclean/       dataset cleaning
Dataset/
  Content/, Image/ collected reports
  IntelliJson/     extracted knowledge, one directory per report
  NPM/, PYPI/      evaluation datasets (package archives)
KnowledgeBase/     knowledge_base.json, snippet embeddings, clusters
Configs/           LLM configuration
```

## Setup

Python 3.10 or later.

```bash
pip install openai numpy tiktoken tenacity requests tqdm hdbscan scikit-learn beautifulsoup4 selenium
npm install -g @cs-au-dk/jelly      # JavaScript call graphs
pip install pycg                    # Python call graphs (or set PYCG_BIN)
```

Fill in the API keys in `Configs/llm_config.json`. The `query_type` and
`embedding_backend` fields choose the provider (`openai`, `azure`, `ollama` or
`custom`); each provider has its own block under `llm_providers` and
`embedding_providers`. A different config file can be given with
`LLM_CONFIG_PATH`.

## Usage

Extract knowledge from the collected reports:

```bash
python Codes/GPTAnalysis/run_multiprocess.py
```

Build the knowledge base and its clusters from `Dataset/IntelliJson`:

```bash
python Codes/KnowledgeBase/build_knowledge_base.py
```

Detect one package (an unpacked package directory):

```bash
python Codes/Detect/run_detection.py <package_dir> npm
python Codes/Detect/run_detection.py <package_dir> pypi
python Codes/Detect/package_detector.py <package_dir> -m npm -j 4 -o report.json
```

Run detection over a dataset laid out as `unzip_<label>/<pkg>/<version>/`:

```bash
python Codes/Detect/run_npm_dataset.py --dataset-root <dir> --output-root <dir> --limit 0
```

The report of a package lists every slice with its trigger, sensitive APIs,
retrieved knowledge and the LLM verdict, and marks the package as malicious if
any slice is judged malicious.

## Datasets

- `Dataset/IntelliJson`: 4,420 verified reports of malicious packages from 22
  intelligence sources, each with the package, its malicious snippets, behaviors,
  attack chain and detection knowledge. Sources whose articles contain no
  relevant report after filtering have no directory here.
- `KnowledgeBase`: the knowledge base built from these reports (7,889 snippets).
- `Dataset/NPM/evaluation` and `Dataset/PYPI/{evaluation,obfuscation}`: the
  benign and malicious package archives used in the evaluation
  (`zip_benign`, `zip_malware`). Unpack them into `unzip_benign` and
  `unzip_malware` before running the detection.

## Citation

```bibtex
@inproceedings{guo2026intelguard,
  title     = {Bridging Expert Reasoning and LLM Detection: A Knowledge-Driven Framework for Malicious Packages},
  author    = {Guo, Wenbo and Song, Shiwen and Guo, Jiaxun and Xu, Zhengzi and Liu, Chengwei and Ou, Haoran and Ge, Mengmeng and Liu, Yang},
  booktitle = {Proceedings of the ACM Web Conference 2026 (WWW '26)},
  year      = {2026},
  pages     = {3554--3565},
  doi       = {10.1145/3774904.3792083}
}
```
