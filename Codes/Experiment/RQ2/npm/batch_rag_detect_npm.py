#!/usr/bin/env python3
"""Batch detection over the npm evaluation dataset."""

import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Tuple, Optional
from multiprocessing import Pool
from datetime import datetime

project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
print(project_root)
sys.path.insert(0, str(project_root))

from Codes.Detect.package_detector import PackageMalwareDetector
from Codes.GPTAnalysis.llmquery import LLMAgent

PROJECT_ROOT = Path(__file__).resolve().parents[4]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


DATASETS = {
    "evaluation": {
        "benign": f"{PROJECT_ROOT}/Dataset/NPM/evaluation/unzip_benign",
        "malware": f"{PROJECT_ROOT}/Dataset/NPM/evaluation/unzip_malware",
    }
}

RESULT_BASE = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results"

MAX_JS_FILES = 10
NUM_PROCESSES = 20

SIMILARITY_THRESHOLD = None

PACKAGE_MANAGER = "npm"


def select_js_files(package_path: Path, max_files: Optional[int] = 10) -> List[Path]:
    """JavaScript files to analyze, priority files first."""
    exclude_dirs = {'node_modules', '.git', 'test', 'tests', '__tests__', 
                   'dist', 'build', 'coverage', '.nyc_output'}
    
    all_files = []
    
    for js_file in package_path.rglob('*.js'):
        if any(excluded in js_file.parts for excluded in exclude_dirs):
            continue
        all_files.append(js_file)
    
    for sh_file in package_path.rglob('*.sh'):
        if any(excluded in sh_file.parts for excluded in exclude_dirs):
            continue
        all_files.append(sh_file)
    
    package_json = package_path / 'package.json'
    if package_json.exists():
        all_files.append(package_json)
    
    priority_files = []
    normal_files = []
    
    for file in all_files:
        file_name = file.name.lower()
        if file_name == 'index.js' or file_name == 'package.json':
            priority_files.append(file)
        else:
            normal_files.append(file)
    
    priority_files.sort(key=lambda x: (x.name != 'index.js', x.name != 'package.json', str(x)))
    
    normal_files.sort(key=lambda x: str(x))
    
    if max_files is None:
        selected_files = priority_files + normal_files
    else:
        selected_files = priority_files + normal_files[:max_files]
    
    return selected_files


def detect_single_package(args: Tuple[str, str, str, str]) -> dict:
    """Worker: detect one package."""
    package_path, package_name, dataset_type, label = args
    
    try:
        logger.info(f"Starting detection: {dataset_type}/{label}/{package_name}")
        
        package_path_obj = Path(package_path)
        selected_files = select_js_files(package_path_obj, max_files=MAX_JS_FILES)
        
        if not selected_files:
            logger.warning(f"  {package_name}: No JavaScript files found")
            return {
                "package_name": package_name,
                "dataset_type": dataset_type,
                "label": label,
                "status": "no_js_files",
                "error": "No JavaScript files found in package"
            }
        
        logger.info(f"  {package_name}: Selected {len(selected_files)} files for analysis")
        
        llm_agent = LLMAgent()
        detector = PackageMalwareDetector(
            llm_agent=llm_agent,
            similarity_threshold=SIMILARITY_THRESHOLD
        )
        
        original_scan = detector._scan_code_files
        
        def custom_scan(pkg_path, pkg_manager):
            """Files to analyze."""
            return selected_files
        
        detector._scan_code_files = custom_scan
        
        result = detector.detect_package(
            package_path=package_path,
            package_manager=PACKAGE_MANAGER,
            output_json=None
        )
        
        result_dict = {
            "package_name": package_name,
            "dataset_type": dataset_type,
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
            "file_results": []
        }
        
        for file_result in result.file_results:
            file_dict = {
                "file_path": file_result.file_path,
                "status": file_result.status,
                "is_malicious": file_result.is_malicious,
                "total_slices": file_result.total_slices,
                "malicious_slices": file_result.malicious_slices,
                "slice_results": []
            }
            
            for slice_result in file_result.slice_results:
                slice_dict = {
                    "slice_id": slice_result.slice_id,
                    "code_snippet": slice_result.code_snippet,
                    "is_malicious": slice_result.is_malicious,
                    "malice_score": slice_result.malice_score,
                    "confidence": slice_result.confidence,
                    "behavior_summary": slice_result.behavior_summary,
                    "explanation": slice_result.explanation,
                    "matched_knowledge_count": len(slice_result.matched_knowledge),
                    "matched_knowledge": slice_result.matched_knowledge
                }
                file_dict["slice_results"].append(slice_dict)
            
            result_dict["file_results"].append(file_dict)
        
        logger.info(f"✅ {package_name}: {'MALICIOUS' if result.is_malicious_package else 'BENIGN'} "
                   f"(Files: {result.malicious_files}/{result.total_files}, "
                   f"Slices: {result.malicious_slices}/{result.total_slices})")
        
        return result_dict
        
    except Exception as e:
        logger.error(f"❌ {package_name}: Detection failed - {e}")
        import traceback
        return {
            "package_name": package_name,
            "dataset_type": dataset_type,
            "label": label,
            "detection_time": datetime.now().isoformat(),
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def check_result_exists(package_name: str, dataset_type: str, label: str) -> bool:
    """Whether a result file exists."""
    output_dir = Path(RESULT_BASE) / dataset_type / "malkg" / label
    output_file = output_dir / f"{package_name}.json"
    return output_file.exists()


def collect_packages(skip_existing: bool = True) -> List[Tuple[str, str, str, str]]:
    """All packages to detect."""
    packages = []
    skipped_count = 0
    
    for dataset_type, paths in DATASETS.items():
        for label, base_path in paths.items():
            base_path_obj = Path(base_path)
            
            if not base_path_obj.exists():
                logger.warning(f"Path does not exist, skipping: {base_path}")
                continue
            
            for package_dir in sorted(base_path_obj.iterdir()):
                if package_dir.is_dir():
                    package_name = package_dir.name
                    
                    if skip_existing and check_result_exists(package_name, dataset_type, label):
                        skipped_count += 1
                        logger.debug(f"⏭️  Skipping {package_name} (result already exists)")
                        continue
                    
                    packages.append((
                        str(package_dir),
                        package_name,
                        dataset_type,
                        label
                    ))
    
    if skipped_count > 0:
        logger.info(f"⏭️  Skipped {skipped_count} packages (results already exist)")
    
    packages.sort(key=lambda x: (
        0 if x[3] == 'malware' else 1,
        x[2],
        x[1]
    ))
    
    return packages


def save_result(result: dict):
    """Write one result file."""
    dataset_type = result["dataset_type"]
    label = result["label"]
    package_name = result["package_name"]
    
    output_dir = Path(RESULT_BASE) / dataset_type / "malkg" / label
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{package_name}.json"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    absolute_path = output_file.resolve()
    logger.info(f"💾 Result saved: {absolute_path}")


def main():
    """Entry point."""
    
    print("\n" + "="*80)
    print("🔍 Batch RAG Malware Detection System (NPM)")
    print("="*80)
    print(f"📊 Datasets: {list(DATASETS.keys())}")
    print(f"⚙️  Max files per package: {MAX_JS_FILES if MAX_JS_FILES else 'unlimited'}")
    print(f"⚙️  Parallel processes: {NUM_PROCESSES}")
    print(f"⏭️  Skip existing results: Yes")
    print(f"📦 Package manager: {PACKAGE_MANAGER}")
    print(f"🎯 RAG similarity threshold: {SIMILARITY_THRESHOLD if SIMILARITY_THRESHOLD is not None else 'None (no filtering)'}")
    print(f"📁 Results directory: {RESULT_BASE}")
    print("="*80 + "\n")
    
    logger.info("Collecting package list...")
    packages = collect_packages(skip_existing=True)
    
    if not packages:
        logger.error("❌ No packages found, exiting")
        return 1
    
    logger.info(f"✅ Found {len(packages)} packages")
    
    stats = {}
    for _, _, dataset_type, label in packages:
        key = f"{dataset_type}/{label}"
        stats[key] = stats.get(key, 0) + 1
    
    print("\n📊 Package distribution:")
    for key, count in sorted(stats.items()):
        print(f"  {key}: {count} packages")
    print()
    
    logger.info(f"Starting batch detection (using {NUM_PROCESSES} processes)...")
    
    start_time = datetime.now()
    success_count = 0
    error_count = 0
    
    with Pool(processes=NUM_PROCESSES) as pool:
        for i, result in enumerate(pool.imap(detect_single_package, packages), 1):
            save_result(result)
            
            if result["status"] == "success":
                success_count += 1
            else:
                error_count += 1
            
            progress = (i / len(packages)) * 100
            logger.info(f"Progress: {i}/{len(packages)} ({progress:.1f}%) - "
                       f"Success: {success_count}, Failed: {error_count}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "="*80)
    print("✅ Batch Detection Complete!")
    print("="*80)
    print(f"⏱️  Total time: {duration:.1f} seconds")
    print(f"📦 Total packages: {len(packages)}")
    print(f"✅ Success: {success_count}")
    print(f"❌ Failed: {error_count}")
    print(f"📁 Results saved in: {RESULT_BASE}")
    print("="*80 + "\n")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted, exiting...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
