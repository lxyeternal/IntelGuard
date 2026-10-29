#!/usr/bin/env python3
"""Batch detection over a dataset laid out as unzip_<label>/<pkg>/<version>/."""

import argparse
import json
import logging
import sys
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from Codes.Detect.package_detector import PackageMalwareDetector
from Codes.GPTAnalysis.llmquery import LLMAgent

LABELS = ("benign", "malware")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("run_npm_dataset")


def iter_packages(dataset_root: Path, label: str):
    """Yield (pkg_name, version, version_dir) under unzip_<label>."""
    root = dataset_root / f"unzip_{label}"
    if not root.is_dir():
        log.warning(f"dataset root missing: {root}")
        return
    for pkg_dir in sorted(root.iterdir()):
        if not pkg_dir.is_dir():
            continue
        for version_dir in sorted(pkg_dir.iterdir()):
            if version_dir.is_dir():
                yield pkg_dir.name, version_dir.name, version_dir


def run_one(detector, version_dir: Path, pkg_name: str, version: str,
            out_file: Path, file_jobs: int) -> dict:
    """Detect one package version and write its report."""
    out_file.parent.mkdir(parents=True, exist_ok=True)

    result = detector.detect_package(
        package_path=str(version_dir),
        package_manager="npm",
        output_json=None,
        num_processes=file_jobs,
    )

    result.package_name = pkg_name
    payload = result.to_dict()
    payload["package_info"]["package_name"] = pkg_name
    payload["package_info"]["package_version"] = version

    flat = {
        "package_name": pkg_name, "package_version": version, "label": out_file.parent.parent.parent.name,
        "detection_time": result.detection_timestamp, "status": "success",
        "selected_files_count": result.total_files,
        "selected_files": [fr.file_path for fr in result.file_results],
        "is_malicious": bool(result.is_malicious_package),
        "total_files": result.total_files, "malicious_files": sum(1 for fr in result.file_results if fr.is_malicious),
        "total_slices": result.total_slices, "malicious_slices": result.malicious_slices,
        "slicer": payload.get("knowledge_base_info", {}).get("slicer"),
        "slicer_stats": payload.get("knowledge_base_info", {}).get("slicer_stats", {}),
        "clusters": payload.get("knowledge_base_info", {}).get("clusters", {}),
        "file_results": [{
            "file_path": fr.file_path, "status": fr.status, "is_malicious": fr.is_malicious,
            "total_slices": fr.total_slices, "malicious_slices": fr.malicious_slices, "error": fr.error,
            "slice_results": [{
                "slice_id": sr.slice_id, "code_snippet": sr.code_snippet, "is_malicious": sr.is_malicious,
                "malice_score": sr.malice_score, "confidence": sr.confidence,
                "behavior_summary": sr.behavior_summary, "explanation": sr.explanation,
                "slice_meta": sr.slice_meta or {},
                "matched_knowledge_count": len(sr.matched_knowledge),
                "matched_knowledge": sr.matched_knowledge,
            } for sr in fr.slice_results],
        } for fr in result.file_results],
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(flat, f, indent=2, ensure_ascii=False)

    return payload


def main():
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset-root", type=Path, required=True, help="dir containing unzip_benign/ and unzip_malware/")
    parser.add_argument("--output-root", type=Path, required=True, help="where <label>/<pkg>/<version>/result.json is written")
    parser.add_argument("--label", choices=("benign", "malware", "both"), default="both")
    parser.add_argument("--limit", type=int, default=3,
                        help="Max packages to process per label. 0 = no limit. Default: 3 (smoke test).")
    parser.add_argument("--file-jobs", type=int, default=1,
                        help="Per-package file-level parallelism (1=single, 0=auto, >1=fixed).")
    parser.add_argument("--kb-path", type=Path, default=None, help="knowledge base dir (default: IntelliGraph/KnowledgeBase or $INTELGUARD_KB_PATH)")
    parser.add_argument("--no-skip", action="store_true",
                        help="Re-detect packages even if result.json already exists.")
    parser.add_argument("--shard", default="0/1",
                        help="i/n: process only every n-th package (index %% n == i) so several processes can split the dataset.")
    parser.add_argument("--only-list", type=Path, default=None,
                        help="text file with one '<label>/<pkg>/<version>' per line; packages not listed are skipped")
    args = parser.parse_args()
    shard_i, shard_n = (int(x) for x in args.shard.split("/"))
    only = None
    if args.only_list:
        only = {l.strip() for l in open(args.only_list, encoding="utf-8") if l.strip()}
        log.info(f"  only_list  : {args.only_list} ({len(only)} entries)")

    labels = LABELS if args.label == "both" else (args.label,)

    log.info("=" * 78)
    log.info("IntelliGraph batch detection over NPMAnalysis")
    log.info(f"  dataset    : {args.dataset_root}")
    log.info(f"  output     : {args.output_root}")
    log.info(f"  labels     : {labels}")
    log.info(f"  limit/lab  : {args.limit if args.limit > 0 else 'unlimited'}")
    log.info(f"  file_jobs  : {args.file_jobs}")
    log.info(f"  skip_done  : {not args.no_skip}")
    log.info(f"  shard      : {shard_i}/{shard_n}")
    log.info("=" * 78)

    log.info("Initializing detector (loads KB once)...")
    shared_agent = LLMAgent()
    detector = PackageMalwareDetector(kb_path=str(args.kb_path) if args.kb_path else None, llm_agent=shared_agent)

    overall = {"benign": {"done": 0, "skip": 0, "fail": 0, "malicious": 0},
               "malware": {"done": 0, "skip": 0, "fail": 0, "malicious": 0}}
    t_start = time.time()

    for label in labels:
        log.info(f"\n>>> Label = {label} <<<")
        out_root = args.output_root / label
        out_root.mkdir(parents=True, exist_ok=True)

        processed = 0
        todo = [(p, v, d) for p, v, d in iter_packages(args.dataset_root, label)
                if only is None or f"{label}/{p}/{v}" in only]
        for idx, (pkg_name, version, version_dir) in enumerate(todo):
            if idx % shard_n != shard_i:
                continue
            if args.limit > 0 and processed >= args.limit:
                break

            out_file = out_root / pkg_name / version / "result.json"

            if out_file.exists() and not args.no_skip:
                overall[label]["skip"] += 1
                continue

            processed += 1
            t0 = time.time()
            log.info(f"[{label}][{processed}] {pkg_name}/{version}")

            try:
                payload = run_one(detector, version_dir, pkg_name, version,
                                  out_file, args.file_jobs)
                is_mal = payload["detection_summary"]["is_malicious_package"]
                n_slc = payload["detection_summary"]["total_code_slices"]
                n_mal = payload["detection_summary"]["malicious_slices_found"]
                dt = time.time() - t0
                log.info(f"    -> {'MALICIOUS' if is_mal else 'BENIGN'}  "
                         f"slices={n_slc} mal_slices={n_mal} elapsed={dt:.1f}s  "
                         f"saved={out_file}")
                overall[label]["done"] += 1
                if is_mal:
                    overall[label]["malicious"] += 1
            except Exception as e:
                overall[label]["fail"] += 1
                log.error(f"    !! FAILED: {e}")
                err_file = out_file.parent / "error.log"
                err_file.parent.mkdir(parents=True, exist_ok=True)
                with open(err_file, "w") as f:
                    f.write(f"{e}\n\n{traceback.format_exc()}")

    elapsed = time.time() - t_start
    log.info("\n" + "=" * 78)
    log.info(f"Done in {elapsed:.1f}s")
    for label in labels:
        s = overall[label]
        log.info(f"  {label:7s}  done={s['done']:>5}  skip={s['skip']:>5}  "
                 f"fail={s['fail']:>5}  predicted_malicious={s['malicious']}")
    log.info("=" * 78)


if __name__ == "__main__":
    main()
