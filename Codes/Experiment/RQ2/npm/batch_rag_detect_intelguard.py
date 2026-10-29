#!/usr/bin/env python3
"""Batch detection over a dataset laid out as unzip_<label>/<pkg>/<version>/."""

import json
import logging
import os
import sys
import traceback
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Tuple
from multiprocessing import Pool

project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.Detect.package_detector import PackageMalwareDetector
from Codes.GPTAnalysis.llmquery import LLMAgent

NPMANALYSIS_ROOT = os.environ.get("NPMANALYSIS_ROOT", "NPMAnalysis")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


DATASETS = {
    "benign":  f"{NPMANALYSIS_ROOT}/Dataset/unzip_benign",
    "malware": f"{NPMANALYSIS_ROOT}/Dataset/unzip_malware",
}

RESULT_BASE = f"{NPMANALYSIS_ROOT}/Experiment/Results/IntelGuard"

EXCLUSION_FILES = {
    "benign":  f"{NPMANALYSIS_ROOT}/Core/Data/cleaning/benign_packages_excluded_from_uploaded_dataset.txt",
    "malware": f"{NPMANALYSIS_ROOT}/Core/Data/cleaning/malware_packages_excluded_from_uploaded_dataset.txt",
}

MAX_JS_FILES = 10
NUM_PROCESSES = 20
SIMILARITY_THRESHOLD = None

PACKAGE_MANAGER = "npm"


def select_js_files(package_path: Path, max_files: Optional[int] = 10) -> List[Path]:
    """JavaScript files to analyze, priority files first."""
    exclude_dirs = {'node_modules', '.git', 'test', 'tests', '__tests__',
                    'dist', 'build', 'coverage', '.nyc_output'}

    all_files: List[Path] = []

    for js_file in package_path.rglob('*.js'):
        if any(excluded in js_file.parts for excluded in exclude_dirs):
            continue
        all_files.append(js_file)

    for sh_file in package_path.rglob('*.sh'):
        if any(excluded in sh_file.parts for excluded in exclude_dirs):
            continue
        all_files.append(sh_file)

    for pj_file in package_path.rglob('package.json'):
        if any(excluded in pj_file.parts for excluded in exclude_dirs):
            continue
        all_files.append(pj_file)

    priority_files: List[Path] = []
    normal_files: List[Path] = []
    for f in all_files:
        name = f.name.lower()
        if name in ('package.json', 'index.js'):
            priority_files.append(f)
        else:
            normal_files.append(f)

    priority_files.sort(key=lambda x: (x.name != 'package.json', str(x)))
    normal_files.sort(key=lambda x: str(x))

    if max_files is None:
        selected = priority_files + normal_files
    else:
        selected = priority_files + normal_files[:max_files]
    return selected


def detect_single_package(args: Tuple[str, str, str, str]) -> dict:
    """Worker: detect one package version."""
    package_path, package_name, version, label = args

    try:
        logger.info(f"Starting detection: {label}/{package_name}/{version}")

        package_path_obj = Path(package_path)
        selected_files = select_js_files(package_path_obj, max_files=MAX_JS_FILES)

        if not selected_files:
            logger.warning(f"  {package_name}/{version}: No JavaScript files found")
            return {
                "package_name": package_name,
                "package_version": version,
                "label": label,
                "status": "no_js_files",
                "error": "No JavaScript files found in package",
                "detection_time": datetime.now().isoformat(),
            }

        logger.info(f"  {package_name}/{version}: Selected {len(selected_files)} files")

        llm_agent = LLMAgent()
        detector = PackageMalwareDetector(
            llm_agent=llm_agent,
            similarity_threshold=SIMILARITY_THRESHOLD,
        )

        def custom_scan(pkg_path, pkg_manager):
            """Files to analyze."""
            return selected_files
        detector._scan_code_files = custom_scan

        result = detector.detect_package(
            package_path=package_path,
            package_manager=PACKAGE_MANAGER,
            output_json=None,
        )

        result_dict = {
            "package_name": package_name,
            "package_version": version,
            "label": label,
            "detection_time": datetime.now().isoformat(),
            "status": "success",
            "selected_files_count": len(selected_files),
            "selected_files": [str(f.relative_to(package_path_obj)) for f in selected_files],
            "is_malicious": result.is_malicious_package,
            "total_files": result.total_files,
            "malicious_files": result.malicious_files,
            "total_slices": result.total_slices,
            "malicious_slices": result.malicious_slices,
            "file_results": [],
        }

        for file_result in result.file_results:
            file_dict = {
                "file_path": file_result.file_path,
                "status": file_result.status,
                "is_malicious": file_result.is_malicious,
                "total_slices": file_result.total_slices,
                "malicious_slices": file_result.malicious_slices,
                "slice_results": [],
            }
            for slice_result in file_result.slice_results:
                file_dict["slice_results"].append({
                    "slice_id": slice_result.slice_id,
                    "code_snippet": slice_result.code_snippet,
                    "is_malicious": slice_result.is_malicious,
                    "malice_score": slice_result.malice_score,
                    "confidence": slice_result.confidence,
                    "behavior_summary": slice_result.behavior_summary,
                    "explanation": slice_result.explanation,
                    "matched_knowledge_count": len(slice_result.matched_knowledge),
                    "matched_knowledge": slice_result.matched_knowledge,
                })
            result_dict["file_results"].append(file_dict)

        logger.info(
            f"✅ {package_name}/{version}: "
            f"{'MALICIOUS' if result.is_malicious_package else 'BENIGN'}  "
            f"(Files: {result.malicious_files}/{result.total_files}, "
            f"Slices: {result.malicious_slices}/{result.total_slices})"
        )
        return result_dict

    except Exception as e:
        logger.error(f"❌ {package_name}/{version}: Detection failed - {e}")
        return {
            "package_name": package_name,
            "package_version": version,
            "label": label,
            "detection_time": datetime.now().isoformat(),
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


def result_path(label: str, package_name: str, version: str) -> Path:
    """Result file of a package version."""
    return Path(RESULT_BASE) / label / package_name / version / "result.json"


def check_result_exists(package_name: str, version: str, label: str) -> bool:
    """Whether a result file exists."""
    return result_path(label, package_name, version).exists()


def load_exclusions() -> set:
    """Excluded (label, package, version) tuples."""
    excluded = set()
    for label, path in EXCLUSION_FILES.items():
        p = Path(path)
        if not p.exists():
            logger.warning(f"Exclusion file missing, skipping: {path}")
            continue
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('/')
                if len(parts) < 4:
                    continue
                zip_label = parts[-3]
                pkg = parts[-2]
                version = parts[-1]
                line_label = zip_label.replace('zip_', '', 1)
                if line_label != label:
                    logger.debug(f"Label mismatch in {path}: line says '{line_label}' but file is for '{label}'")
                excluded.add((line_label, pkg, version))
    logger.info(f"📋 Loaded {len(excluded)} exclusions from cleaning lists")
    return excluded


def collect_packages(skip_existing: bool = True) -> List[Tuple[str, str, str, str]]:
    """All package versions to detect."""
    excluded = load_exclusions()
    packages: List[Tuple[str, str, str, str]] = []
    skipped_existing = 0
    skipped_excluded = 0

    for label, base_path in DATASETS.items():
        base = Path(base_path)
        if not base.exists():
            logger.warning(f"Path does not exist, skipping: {base_path}")
            continue

        for package_dir in sorted(base.iterdir()):
            if not package_dir.is_dir():
                continue
            package_name = package_dir.name

            for version_dir in sorted(package_dir.iterdir()):
                if not version_dir.is_dir():
                    continue
                version = version_dir.name

                if (label, package_name, version) in excluded:
                    skipped_excluded += 1
                    continue

                if skip_existing and check_result_exists(package_name, version, label):
                    skipped_existing += 1
                    continue

                packages.append((
                    str(version_dir),
                    package_name,
                    version,
                    label,
                ))

    if skipped_excluded > 0:
        logger.info(f"🚫 Skipped {skipped_excluded} (pkg, version) pairs (in exclusion lists)")
    if skipped_existing > 0:
        logger.info(f"⏭️  Skipped {skipped_existing} (pkg, version) pairs (results already exist)")

    packages.sort(key=lambda x: (
        0 if x[3] == 'malware' else 1,
        x[1],
        x[2],
    ))
    return packages


def save_result(result: dict):
    """Write one result file."""
    label = result["label"]
    package_name = result["package_name"]
    version = result["package_version"]

    out_file = result_path(label, package_name, version)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    logger.info(f"💾 Result saved: {out_file}")


def main():
    """Entry point."""
    print("\n" + "=" * 80)
    print("🔍 Batch RAG Malware Detection — NPMAnalysis / IntelGuard layout")
    print("=" * 80)
    print(f"📊 Labels                 : {list(DATASETS.keys())}")
    print(f"⚙️  Max files per package  : {MAX_JS_FILES if MAX_JS_FILES else 'unlimited'}")
    print(f"⚙️  Parallel processes     : {NUM_PROCESSES}")
    print(f"⏭️  Skip existing results  : Yes")
    print(f"📦 Package manager        : {PACKAGE_MANAGER}")
    print(f"🎯 RAG similarity threshold: {SIMILARITY_THRESHOLD if SIMILARITY_THRESHOLD is not None else 'None (no filtering)'}")
    print(f"📁 Output base            : {RESULT_BASE}")
    print("=" * 80 + "\n")

    logger.info("Collecting package list...")
    packages = collect_packages(skip_existing=True)

    if not packages:
        logger.error("❌ No (pkg, version) pairs found, exiting")
        return 1

    logger.info(f"✅ Found {len(packages)} (pkg, version) pairs")

    stats = {}
    for _, _, _, label in packages:
        stats[label] = stats.get(label, 0) + 1

    print("\n📊 Distribution:")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")
    print()

    logger.info(f"Starting batch detection (using {NUM_PROCESSES} processes)...")
    start = datetime.now()
    success = 0
    failed = 0

    with Pool(processes=NUM_PROCESSES) as pool:
        for i, result in enumerate(pool.imap(detect_single_package, packages), 1):
            save_result(result)
            if result["status"] == "success":
                success += 1
            else:
                failed += 1
            pct = i / len(packages) * 100
            logger.info(f"Progress: {i}/{len(packages)} ({pct:.1f}%)  ok={success} fail={failed}")

    duration = (datetime.now() - start).total_seconds()
    print("\n" + "=" * 80)
    print("✅ Batch Detection Complete!")
    print("=" * 80)
    print(f"⏱️  Total time: {duration:.1f}s")
    print(f"📦 Total      : {len(packages)}")
    print(f"✅ Success    : {success}")
    print(f"❌ Failed     : {failed}")
    print(f"📁 Output base: {RESULT_BASE}")
    print("=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted, exiting...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal: {e}")
        traceback.print_exc()
        sys.exit(1)
