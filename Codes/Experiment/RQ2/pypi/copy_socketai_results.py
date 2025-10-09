#!/usr/bin/env python3
"""
复制socketai的检测结果到对应的数据集结构中
"""

import os
import shutil
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

# 数据集路径
DATASET_PATHS = {
    'obfuscation': '/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/obfuscation',
    'regular': '/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/regular',
}

# socketai结果路径
SOCKETAI_RESULTS = {
    'evaluation': '/home2/wenbo/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/evaluation/socketai',
    'obfuscation': '/home2/wenbo/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/obfuscation/socketai',
}

# 目标路径
TARGET_BASE = '/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results'


def get_package_names(dataset_path):
    """从数据集中获取所有包名"""
    packages = {'benign': set(), 'malware': set()}
    
    # 扫描zip_benign
    benign_path = Path(dataset_path) / 'zip_benign'
    if benign_path.exists():
        packages['benign'] = set(os.listdir(benign_path))
        print(f"Found {len(packages['benign'])} benign packages in {benign_path}")
    
    # 扫描zip_malware
    malware_path = Path(dataset_path) / 'zip_malware'
    if malware_path.exists():
        packages['malware'] = set(os.listdir(malware_path))
        print(f"Found {len(packages['malware'])} malware packages in {malware_path}")
    
    return packages


def copy_single_package(args):
    """复制单个包（用于并行处理）"""
    pkg_name, src, dst = args
    try:
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        return (pkg_name, True, None)
    except Exception as e:
        return (pkg_name, False, str(e))


def copy_socketai_results(dataset_type, socketai_type, max_workers=8):
    """
    复制socketai结果（并行版本）
    
    Args:
        dataset_type: 'obfuscation' 或 'regular'
        socketai_type: 'evaluation' 或 'obfuscation'
        max_workers: 并行工作进程数
    """
    print(f"\n{'='*80}")
    print(f"Processing: dataset={dataset_type}, socketai={socketai_type}")
    print(f"{'='*80}\n")
    
    # 获取数据集中的包名
    dataset_path = DATASET_PATHS[dataset_type]
    packages = get_package_names(dataset_path)
    
    # socketai结果路径
    socketai_base = Path(SOCKETAI_RESULTS[socketai_type])
    
    # 目标路径
    target_base = Path(TARGET_BASE) / socketai_type / 'socketai'
    
    copied_count = {'benign': 0, 'malware': 0}
    not_found = {'benign': [], 'malware': []}
    errors = {'benign': [], 'malware': []}
    
    # 处理benign和malware
    for label in ['benign', 'malware']:
        socketai_label_path = socketai_base / label
        target_label_path = target_base / label
        
        # 创建目标目录
        target_label_path.mkdir(parents=True, exist_ok=True)
        
        if not socketai_label_path.exists():
            print(f"Warning: {socketai_label_path} does not exist!")
            continue
        
        # 获取socketai中所有的结果文件夹
        socketai_packages = {}
        for item in os.listdir(socketai_label_path):
            item_path = socketai_label_path / item
            if item_path.is_dir():
                socketai_packages[item] = item_path
        
        print(f"\n{label.upper()}: Checking {len(packages[label])} packages from dataset")
        print(f"Available in socketai: {len(socketai_packages)} packages")
        
        # 准备复制任务
        copy_tasks = []
        for pkg_name in packages[label]:
            if pkg_name in socketai_packages:
                src = socketai_packages[pkg_name]
                dst = target_label_path / pkg_name
                copy_tasks.append((pkg_name, src, dst))
            else:
                not_found[label].append(pkg_name)
        
        print(f"Copying {len(copy_tasks)} packages using {max_workers} workers...")
        
        # 并行复制
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(copy_single_package, task): task for task in copy_tasks}
            
            with tqdm(total=len(copy_tasks), desc=f"{label.upper()}", unit="pkg") as pbar:
                for future in as_completed(futures):
                    pkg_name, success, error = future.result()
                    if success:
                        copied_count[label] += 1
                    else:
                        errors[label].append((pkg_name, error))
                    pbar.update(1)
        
        print(f"\n{label.upper()} Summary:")
        print(f"  - Copied: {copied_count[label]}")
        print(f"  - Not found: {len(not_found[label])}")
        print(f"  - Errors: {len(errors[label])}")
        
        if not_found[label] and len(not_found[label]) <= 10:
            print(f"  Not found packages (first 10): {not_found[label][:10]}")
        
        if errors[label]:
            print(f"  Errors (first 5): {errors[label][:5]}")
    
    return copied_count, not_found


def main():
    """主函数"""
    print("Starting to copy socketai results...\n")
    
    total_results = {}
    
    # evaluation对应regular数据集
    total_results['regular_evaluation'] = copy_socketai_results('regular', 'evaluation')
    
    # obfuscation对应obfuscation数据集
    total_results['obfuscation_obfuscation'] = copy_socketai_results('obfuscation', 'obfuscation')
    
    # 打印总结
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}\n")
    
    for key, (copied, not_found) in total_results.items():
        print(f"{key}:")
        print(f"  Benign: {copied['benign']} copied, {len(not_found['benign'])} not found")
        print(f"  Malware: {copied['malware']} copied, {len(not_found['malware'])} not found")
        print()


if __name__ == '__main__':
    main()
