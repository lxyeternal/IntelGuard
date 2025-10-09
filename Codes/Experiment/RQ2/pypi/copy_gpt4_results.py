#!/usr/bin/env python3
"""
复制gpt-4.1的检测结果到对应的数据集结构中
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

# GPT-4.1结果路径
GPT4_RESULTS = {
    'evaluation': '/home2/wenbo/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/evaluation/gpt-4.1',
    'obfuscation': '/home2/wenbo/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/obfuscation/gpt-4.1',
}

# 目标基础路径
TARGET_BASE = '/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results'


def get_package_names(dataset_path):
    """从数据集中获取包名"""
    packages = {'benign': [], 'malware': []}
    
    benign_path = Path(dataset_path) / 'zip_benign'
    malware_path = Path(dataset_path) / 'zip_malware'
    
    if benign_path.exists():
        packages['benign'] = [d.name for d in benign_path.iterdir() if d.is_dir()]
        print(f"Found {len(packages['benign'])} benign packages in {benign_path}")
    
    if malware_path.exists():
        packages['malware'] = [d.name for d in malware_path.iterdir() if d.is_dir()]
        print(f"Found {len(packages['malware'])} malware packages in {malware_path}")
    
    return packages


def copy_single_file(args):
    """复制单个文件（用于并行处理）"""
    pkg_name, src, dst = args
    try:
        # 确保目标目录存在
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return (pkg_name, True, None)
    except Exception as e:
        return (pkg_name, False, str(e))


def copy_gpt4_results(dataset_type, gpt4_type, max_workers=8):
    """
    复制gpt-4.1结果（并行版本）
    
    Args:
        dataset_type: 'obfuscation' 或 'regular'
        gpt4_type: 'evaluation' 或 'obfuscation'
        max_workers: 并行工作进程数
    """
    print(f"\n{'='*80}")
    print(f"Processing: dataset={dataset_type}, gpt4={gpt4_type}")
    print(f"{'='*80}\n")
    
    # 获取数据集中的包名
    dataset_path = DATASET_PATHS[dataset_type]
    packages = get_package_names(dataset_path)
    
    # GPT-4.1结果路径
    gpt4_base = Path(GPT4_RESULTS[gpt4_type])
    
    # 目标路径
    target_base = Path(TARGET_BASE) / gpt4_type / 'gpt-4.1'
    
    copied_count = {'benign': 0, 'malware': 0}
    not_found = {'benign': [], 'malware': []}
    errors = {'benign': [], 'malware': []}
    
    # 处理benign和malware
    for label in ['benign', 'malware']:
        gpt4_label_path = gpt4_base / label
        target_label_path = target_base / label
        
        # 创建目标目录
        target_label_path.mkdir(parents=True, exist_ok=True)
        
        if not gpt4_label_path.exists():
            print(f"Warning: {gpt4_label_path} does not exist!")
            continue
        
        # 获取gpt4中所有的txt文件
        gpt4_files = {}
        for item in os.listdir(gpt4_label_path):
            if item.endswith('.txt'):
                # 去掉.txt后缀得到包名
                pkg_name = item[:-4]  # 移除.txt
                gpt4_files[pkg_name] = gpt4_label_path / item
        
        print(f"\n{label.upper()}: Checking {len(packages[label])} packages from dataset")
        print(f"Available in gpt-4.1: {len(gpt4_files)} packages")
        
        # 准备复制任务
        copy_tasks = []
        for pkg_name in packages[label]:
            if pkg_name in gpt4_files:
                src = gpt4_files[pkg_name]
                # 目标文件保持原名（包含.txt）
                dst = target_label_path / f"{pkg_name}.txt"
                copy_tasks.append((pkg_name, src, dst))
            else:
                not_found[label].append(pkg_name)
        
        print(f"Copying {len(copy_tasks)} files using {max_workers} workers...")
        
        # 并行复制
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(copy_single_file, task): task for task in copy_tasks}
            
            with tqdm(total=len(copy_tasks), desc=f"{label.upper()}", unit="file") as pbar:
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
    print("Starting to copy gpt-4.1 results...\n")
    
    all_results = {}
    
    # 1. evaluation数据集 -> evaluation结果
    print("\n" + "="*80)
    print("Task 1: regular dataset -> evaluation results")
    print("="*80)
    result = copy_gpt4_results('regular', 'evaluation')
    all_results['regular_evaluation'] = result
    
    # 2. obfuscation数据集 -> obfuscation结果
    print("\n" + "="*80)
    print("Task 2: obfuscation dataset -> obfuscation results")
    print("="*80)
    result = copy_gpt4_results('obfuscation', 'obfuscation')
    all_results['obfuscation_obfuscation'] = result
    
    # 打印总结
    print("\n" + "="*80)
    print("FINAL SUMMARY")
    print("="*80)
    
    for task_name, (copied, not_found) in all_results.items():
        print(f"\n{task_name}:")
        print(f"  Benign - Copied: {copied['benign']}, Not found: {len(not_found['benign'])}")
        print(f"  Malware - Copied: {copied['malware']}, Not found: {len(not_found['malware'])}")
    
    print("\nDone!")


if __name__ == '__main__':
    main()
