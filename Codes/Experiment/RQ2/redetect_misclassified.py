#!/usr/bin/env python3
"""
Re-detect Misclassified Packages

This script:
1. Scans result directories to find misclassified packages
   - Benign predicted as malicious (False Positive)
   - Malware predicted as benign (False Negative)
2. Re-runs detection on these packages using the same detection logic
   - Same file selection (priority files + max_files limit)
   - Same slicing logic
   - Same RAG matching and LLM detection
3. Overwrites original JSON files with new detection results
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from multiprocessing import Pool
from datetime import datetime

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.Detect.package_detector import PackageMalwareDetector
from Codes.GPTAnalysis.llmquery import LLMAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ==================== Configuration ====================

# Result directories to scan
RESULT_CONFIGS = [
    {
        "ecosystem": "npm",
        "dataset": "evaluation",
        "result_base": "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/results/evaluation/malkg",
        "source_base": "/home2/wenbo/Documents/IntelliGraph/Dataset/NPM/evaluation",
        "package_manager": "npm",
        "max_files": 20,
        "priority_files": ["package.json", "index.js"],  # package.json优先（包含安装脚本）
        "file_extension": "*.js",
        "exclude_dirs": {'node_modules', '.git', 'test', 'tests', '__tests__', 'dist', 'build', 'coverage', '.nyc_output'}
    }
    # {
    #     "ecosystem": "pypi",
    #     "dataset": "evaluation",
    #     "result_base": "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/evaluation/malkg",
    #     "source_base": "/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/evaluation",
    #     "package_manager": "pypi",
    #     "max_files": 10,
    #     "priority_files": ["setup.py", "__init__.py"],
    #     "file_extension": "*.py",
    #     "exclude_dirs": {'venv', 'env', '.venv', '__pycache__', '.git', 'dist', 'build', '.egg-info', 'test', 'tests'}
    # },
    # {
    #     "ecosystem": "pypi",
    #     "dataset": "obfuscation",
    #     "result_base": "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/obfuscation/malkg",
    #     "source_base": "/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/obfuscation",
    #     "package_manager": "pypi",
    #     "max_files": 10,
    #     "priority_files": ["setup.py", "__init__.py"],
    #     "file_extension": "*.py",
    #     "exclude_dirs": {'venv', 'env', '.venv', '__pycache__', '.git', 'dist', 'build', '.egg-info', 'test', 'tests'}
    # }
]

NUM_PROCESSES = 20  # Number of parallel processes


# ==================== File Selection Logic ====================

def select_files(package_path: Path, config: dict, max_files: Optional[int] = 10) -> List[Path]:
    """
    Select files to analyze based on ecosystem configuration
    
    Args:
        package_path: Package path
        config: Configuration dictionary
        max_files: Max number of files to analyze (excluding priority files), None means all
        
    Returns:
        List of selected files
    """
    exclude_dirs = config['exclude_dirs']
    file_extension = config['file_extension']
    priority_file_names = config['priority_files']
    package_manager = config['package_manager']
    
    # Collect all files matching the extension
    all_files = []
    for file in package_path.rglob(file_extension):
        # Exclude specific directories
        if any(excluded in file.parts for excluded in exclude_dirs):
            continue
        all_files.append(file)
    
    # For npm: also collect .sh files (install scripts)
    if package_manager == 'npm':
        for sh_file in package_path.rglob('*.sh'):
            if any(excluded in sh_file.parts for excluded in exclude_dirs):
                continue
            if sh_file not in all_files:
                all_files.append(sh_file)
    
    # Add priority files explicitly (like package.json, setup.py)
    # 递归查找所有优先文件（不限制位置，只排除特定目录）
    for priority_name in priority_file_names:
        for found_file in package_path.rglob(priority_name):
            if any(excluded in found_file.parts for excluded in exclude_dirs):
                continue
            if found_file not in all_files:
                all_files.append(found_file)
    
    # Classify files
    priority_files = []
    normal_files = []
    
    for file in all_files:
        file_name = file.name.lower()
        if file_name in [pf.lower() for pf in priority_file_names]:
            priority_files.append(file)
        else:
            normal_files.append(file)
    
    # Sort priority files
    priority_files.sort(key=lambda x: (
        priority_file_names.index(x.name.lower()) if x.name.lower() in [pf.lower() for pf in priority_file_names] else len(priority_file_names),
        str(x)
    ))
    
    # Sort normal files (by path)
    normal_files.sort(key=lambda x: str(x))
    
    # Combine results
    if max_files is None:
        selected_files = priority_files + normal_files
    else:
        selected_files = priority_files + normal_files[:max_files]
    
    return selected_files


# ==================== Find Misclassified Packages ====================

def find_misclassified_packages() -> List[Dict]:
    """
    Scan result directories to find misclassified packages
    
    Returns:
        List of misclassified package info dictionaries
    """
    misclassified = []
    
    for config in RESULT_CONFIGS:
        result_base = Path(config['result_base'])
        
        if not result_base.exists():
            logger.warning(f"Result directory does not exist: {result_base}")
            continue
        
        # Check benign folder for false positives
        benign_dir = result_base / "benign"
        if benign_dir.exists():
            for result_file in benign_dir.glob("*.json"):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        result = json.load(f)
                    
                    # Check if benign was predicted as malicious
                    if result.get('is_malicious', False) == True:
                        misclassified.append({
                            "config": config,
                            "package_name": result['package_name'],
                            "true_label": "benign",
                            "predicted_label": "malware",
                            "error_type": "false_positive",
                            "result_file": str(result_file),
                            "original_result": result
                        })
                        logger.info(f"Found FP: {config['ecosystem']}/{config['dataset']}/benign/{result['package_name']}")
                except Exception as e:
                    logger.error(f"Error reading {result_file}: {e}")
        
        # Check malware folder for false negatives
        malware_dir = result_base / "malware"
        if malware_dir.exists():
            for result_file in malware_dir.glob("*.json"):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        result = json.load(f)
                    
                    # Check if malware was predicted as benign
                    if result.get('is_malicious', False) == False:
                        misclassified.append({
                            "config": config,
                            "package_name": result['package_name'],
                            "true_label": "malware",
                            "predicted_label": "benign",
                            "error_type": "false_negative",
                            "result_file": str(result_file),
                            "original_result": result
                        })
                        logger.info(f"Found FN: {config['ecosystem']}/{config['dataset']}/malware/{result['package_name']}")
                except Exception as e:
                    logger.error(f"Error reading {result_file}: {e}")
    
    return misclassified


# ==================== Single Package Re-detection ====================

def redetect_single_package(args: Tuple[Dict, Dict]) -> dict:
    """
    Re-detect a single misclassified package
    
    Args:
        args: (misclassified_info, config)
        
    Returns:
        Detection result dictionary
    """
    misclassified_info = args
    config = misclassified_info['config']
    package_name = misclassified_info['package_name']
    true_label = misclassified_info['true_label']
    
    try:
        logger.info(f"Re-detecting: {config['ecosystem']}/{config['dataset']}/{true_label}/{package_name}")
        
        # 1. Locate source code directory
        source_base = Path(config['source_base'])
        package_path = source_base / f"unzip_{true_label}" / package_name
        
        if not package_path.exists():
            logger.error(f"  {package_name}: Source directory not found: {package_path}")
            return {
                "package_name": package_name,
                "dataset_type": config['dataset'],
                "label": true_label,
                "detection_time": datetime.now().isoformat(),
                "status": "source_not_found",
                "error": f"Source directory not found: {package_path}"
            }
        
        # 2. Select files to analyze
        selected_files = select_files(package_path, config, max_files=config['max_files'])
        
        if not selected_files:
            logger.warning(f"  {package_name}: No files found")
            return {
                "package_name": package_name,
                "dataset_type": config['dataset'],
                "label": true_label,
                "detection_time": datetime.now().isoformat(),
                "status": "no_files",
                "error": "No files found in package"
            }
        
        logger.info(f"  {package_name}: Selected {len(selected_files)} files for re-analysis")
        
        # 3. Create detector
        llm_agent = LLMAgent()
        detector = PackageMalwareDetector(llm_agent=llm_agent)
        
        # 4. Override file scanning logic
        def custom_scan(pkg_path, pkg_manager):
            return selected_files
        
        detector._scan_code_files = custom_scan
        
        # 5. Execute detection
        result = detector.detect_package(
            package_path=str(package_path),
            package_manager=config['package_manager'],
            output_json=None
        )
        
        # 6. Build result (same format as batch_rag_detect.py and batch_rag_detect_npm.py)
        result_dict = {
            "package_name": package_name,
            "dataset_type": config['dataset'],
            "label": true_label,
            "detection_time": datetime.now().isoformat(),
            "status": "success",
            "selected_files_count": len(selected_files),
            "selected_files": [str(f.relative_to(package_path)) for f in selected_files],
            "is_malicious": result.is_malicious_package,
            "total_files": result.total_files,
            "malicious_files": result.malicious_files,
            "total_slices": result.total_slices,
            "malicious_slices": result.malicious_slices,
            "file_results": []
        }
        
        # Add file-level results
        for file_result in result.file_results:
            file_dict = {
                "file_path": file_result.file_path,
                "status": file_result.status,
                "is_malicious": file_result.is_malicious,
                "total_slices": file_result.total_slices,
                "malicious_slices": file_result.malicious_slices,
                "slice_results": []
            }
            
            # Add slice-level results
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
        
        # Check if result changed
        detected_label = "malware" if result.is_malicious_package else "benign"
        result_changed = (detected_label != true_label)
        
        # Get the result file path for logging
        result_file_path = misclassified_info.get('result_file', 'N/A')
        
        # Print with bold if result changed
        if result_changed:
            logger.info(f"\033[1m✅ {package_name}: {'MALICIOUS' if result.is_malicious_package else 'BENIGN'} "
                       f"(Files: {result.malicious_files}/{result.total_files}, "
                       f"Slices: {result.malicious_slices}/{result.total_slices}) "
                       f"[RESULT CHANGED: {true_label} → {detected_label}]\033[0m")
            logger.info(f"   📄 JSON: {result_file_path}")
        else:
            logger.info(f"✅ {package_name}: {'MALICIOUS' if result.is_malicious_package else 'BENIGN'} "
                       f"(Files: {result.malicious_files}/{result.total_files}, "
                       f"Slices: {result.malicious_slices}/{result.total_slices})")
            logger.info(f"   📄 JSON: {result_file_path}")
        
        return result_dict
        
    except Exception as e:
        logger.error(f"❌ {package_name}: Re-detection failed - {e}")
        import traceback
        return {
            "package_name": package_name,
            "dataset_type": config['dataset'],
            "label": true_label,
            "detection_time": datetime.now().isoformat(),
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }


# ==================== Save Results ====================

def save_redetection_result(result: dict, misclassified_info: dict):
    """
    Save re-detection result (overwrite original file)
    
    Args:
        result: Detection result dictionary
        misclassified_info: Original misclassified info
    """
    # Overwrite original file directly
    original_file = Path(misclassified_info['result_file'])
    
    # Save JSON
    with open(original_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    logger.info(f"💾 Re-detection result saved (overwritten): {original_file}")


# ==================== Main Function ====================

def main():
    """Main function"""
    
    print("\n" + "="*80)
    print("🔄 Re-detect Misclassified Packages")
    print("="*80)
    print(f"⚙️  Parallel processes: {NUM_PROCESSES}")
    print("="*80 + "\n")
    
    # 1. Find all misclassified packages
    logger.info("Scanning result directories for misclassified packages...")
    misclassified = find_misclassified_packages()
    
    if not misclassified:
        logger.info("✅ No misclassified packages found!")
        return 0
    
    logger.info(f"Found {len(misclassified)} misclassified packages")
    
    # Statistics
    fp_count = sum(1 for m in misclassified if m['error_type'] == 'false_positive')
    fn_count = sum(1 for m in misclassified if m['error_type'] == 'false_negative')
    
    print("\n📊 Misclassification statistics:")
    print(f"  False Positives (benign → malware): {fp_count}")
    print(f"  False Negatives (malware → benign): {fn_count}")
    
    # Group by ecosystem/dataset
    stats = {}
    for m in misclassified:
        key = f"{m['config']['ecosystem']}/{m['config']['dataset']}/{m['true_label']}"
        stats[key] = stats.get(key, 0) + 1
    
    print("\n📊 Distribution:")
    for key, count in sorted(stats.items()):
        print(f"  {key}: {count} packages")
    print()
    
    # 2. Re-detect packages
    logger.info(f"Starting re-detection (using {NUM_PROCESSES} processes)...")
    
    start_time = datetime.now()
    success_count = 0
    corrected_count = 0
    still_wrong_count = 0
    error_count = 0
    
    with Pool(processes=NUM_PROCESSES) as pool:
        for i, result in enumerate(pool.imap(redetect_single_package, misclassified), 1):
            # Save result
            save_redetection_result(result, misclassified[i-1])
            
            # Statistics
            if result["status"] == "success":
                success_count += 1
                # Check if re-detection matches true label
                true_label = result.get("label")  # benign or malware
                is_malicious = result.get("is_malicious", False)
                is_correct = (is_malicious == (true_label == "malware"))
                
                if is_correct:
                    corrected_count += 1
                else:
                    still_wrong_count += 1
            else:
                error_count += 1
            
            # Display progress
            progress = (i / len(misclassified)) * 100
            logger.info(f"Progress: {i}/{len(misclassified)} ({progress:.1f}%) - "
                       f"Success: {success_count}, Corrected: {corrected_count}, "
                       f"Still Wrong: {still_wrong_count}, Failed: {error_count}")
    
    # 3. Completion statistics
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "="*80)
    print("✅ Re-detection Complete!")
    print("="*80)
    print(f"⏱️  Total time: {duration:.1f} seconds")
    print(f"📦 Total packages: {len(misclassified)}")
    print(f"✅ Success: {success_count}")
    print(f"\033[1m✓  Corrected (now matches true label): {corrected_count}\033[0m")
    print(f"✗  Still wrong: {still_wrong_count}")
    print(f"❌ Failed: {error_count}")
    print("="*80 + "\n")
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  User interrupted, exiting...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Program error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

