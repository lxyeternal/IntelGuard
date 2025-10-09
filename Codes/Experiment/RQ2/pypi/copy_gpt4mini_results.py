#!/usr/bin/env python3
"""
复制 GPT-4.1-mini 的检测结果到 results 目录
GPT-4.1-mini 有两个任务：
1. obfuscation 数据集 -> obfuscation/gpt-4.1-mini (hash格式)
2. evaluation 数据集 -> www_regular/gpt-4.1-mini (package-version格式)
"""

import os
import shutil
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# 配置路径
DATASET_BASE = Path('/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI')
GPT4MINI_RESULTS = {
    'obfuscation': Path('/home2/wenbo/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/obfuscation/gpt-4.1-mini'),
    'www_regular': Path('/home2/wenbo/Documents/PyPIAgent/Codes/tool_detect/detect_output/baselines/www_regular/gpt-4.1-mini'),
}
RESULTS_BASE = Path('/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results')

def get_package_names_hash(dataset_path):
    """从数据集中获取所有包名（hash格式，用于obfuscation）"""
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

def get_package_names_version(dataset_path):
    """从数据集中获取所有包名（package-version格式，用于evaluation）"""
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

def get_available_gpt4mini_results_hash(gpt4mini_dir):
    """获取 GPT-4.1-mini 中所有可用的结果文件（hash格式）"""
    results = {'benign': {}, 'malware': {}}
    
    # 扫描 benign
    benign_dir = gpt4mini_dir / 'benign'
    if benign_dir.exists():
        for file in benign_dir.glob('*.txt'):
            # 文件名格式: {hash}.txt
            hash_name = file.stem
            results['benign'][hash_name] = file
    
    # 扫描 malware
    malware_dir = gpt4mini_dir / 'malware'
    if malware_dir.exists():
        for file in malware_dir.glob('*.txt'):
            # 文件名格式: {hash}##{something}.txt
            # 提取 hash 部分（##之前的部分）
            hash_name = file.stem.split('##')[0]
            # 如果同一个 hash 有多个文件，保留第一个
            if hash_name not in results['malware']:
                results['malware'][hash_name] = file
    
    return results

def get_available_gpt4mini_results_version(gpt4mini_dir):
    """获取 GPT-4.1-mini 中所有可用的结果文件（package-version格式）"""
    results = {'benign': {}, 'malware': {}}
    
    # 扫描 benign
    benign_dir = gpt4mini_dir / 'benign'
    if benign_dir.exists():
        for file in benign_dir.glob('*.txt'):
            # 文件名格式: {package-name}-{version}.txt
            pkg_name = file.stem
            results['benign'][pkg_name] = file
    
    # 扫描 malware
    malware_dir = gpt4mini_dir / 'malware'
    if malware_dir.exists():
        for file in malware_dir.glob('*.txt'):
            # 文件名格式: {package-name}-{version}##{package-name}-{version}.txt
            # 提取 ## 之前的部分
            pkg_name = file.stem.split('##')[0]
            # 如果同一个包有多个文件，保留第一个
            if pkg_name not in results['malware']:
                results['malware'][pkg_name] = file
    
    return results

def copy_file(src_file, dest_file):
    """复制单个文件"""
    try:
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dest_file)
        return True, None
    except Exception as e:
        return False, str(e)

def process_category(packages, available_results, output_dir, category_name, max_workers=8):
    """处理一个类别（benign或malware）的所有包"""
    print(f"\n{category_name.upper()}: Checking {len(packages)} packages from dataset")
    print(f"Available in gpt-4.1-mini: {len(available_results)} packages")
    
    stats = {
        'copied': 0,
        'not_found': 0,
        'errors': 0,
        'not_found_list': [],
        'error_list': []
    }
    
    # 准备复制任务
    copy_tasks = []
    for pkg_hash in packages:
        if pkg_hash in available_results:
            src_file = available_results[pkg_hash]
            dest_file = output_dir / f"{pkg_hash}.txt"
            copy_tasks.append((src_file, dest_file, pkg_hash))
        else:
            stats['not_found'] += 1
            stats['not_found_list'].append(pkg_hash)
    
    # 并行复制文件
    if copy_tasks:
        print(f"Copying {len(copy_tasks)} files using {max_workers} workers...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(copy_file, src, dest): pkg_hash
                for src, dest, pkg_hash in copy_tasks
            }
            
            with tqdm(total=len(copy_tasks), desc=category_name.upper()) as pbar:
                for future in as_completed(futures):
                    pkg_hash = futures[future]
                    success, error = future.result()
                    
                    if success:
                        stats['copied'] += 1
                    else:
                        stats['errors'] += 1
                        stats['error_list'].append((pkg_hash, error))
                    
                    pbar.update(1)
    
    # 打印统计信息
    print(f"\n{category_name.upper()} Summary:")
    print(f"  - Copied: {stats['copied']}")
    print(f"  - Not found: {stats['not_found']}")
    print(f"  - Errors: {stats['errors']}")
    
    if stats['not_found_list'] and len(stats['not_found_list']) <= 10:
        print(f"\n  Not found packages:")
        for pkg in stats['not_found_list'][:10]:
            print(f"    - {pkg}")
    
    if stats['error_list']:
        print(f"\n  Errors:")
        for pkg, error in stats['error_list'][:5]:
            print(f"    - {pkg}: {error}")
    
    return stats

def copy_gpt4mini_results():
    """主函数：复制 GPT-4.1-mini 的结果"""
    print("Starting to copy gpt-4.1-mini results...")
    print("\n")
    
    all_stats = {}
    
    # 任务1: obfuscation 数据集 -> obfuscation/gpt-4.1-mini (hash格式)
    print("=" * 80)
    print("Task 1: obfuscation dataset -> obfuscation/gpt-4.1-mini")
    print("=" * 80)
    print()
    
    dataset_path = DATASET_BASE / 'obfuscation'
    gpt4mini_dir = GPT4MINI_RESULTS['obfuscation']
    output_base = RESULTS_BASE / 'obfuscation' / 'gpt-4.1-mini'
    
    # 获取数据集中的包（hash格式）
    packages = get_package_names_hash(dataset_path)
    
    # 获取 GPT-4.1-mini 中可用的结果（hash格式）
    available_results = get_available_gpt4mini_results_hash(gpt4mini_dir)
    
    # 处理 benign
    benign_output = output_base / 'benign'
    benign_stats = process_category(
        packages['benign'],
        available_results['benign'],
        benign_output,
        'BENIGN'
    )
    
    # 处理 malware
    malware_output = output_base / 'malware'
    malware_stats = process_category(
        packages['malware'],
        available_results['malware'],
        malware_output,
        'MALWARE'
    )
    
    all_stats['obfuscation'] = {
        'benign': benign_stats,
        'malware': malware_stats
    }
    
    # 任务2: evaluation 数据集 -> evaluation/gpt-4.1-mini (package-version格式)
    print("\n" + "=" * 80)
    print("Task 2: evaluation dataset -> evaluation/gpt-4.1-mini")
    print("=" * 80)
    print()
    
    dataset_path = DATASET_BASE / 'regular'
    gpt4mini_dir = GPT4MINI_RESULTS['www_regular']
    output_base = RESULTS_BASE / 'evaluation' / 'gpt-4.1-mini'
    
    # 获取数据集中的包（package-version格式）
    packages = get_package_names_version(dataset_path)
    
    # 获取 GPT-4.1-mini 中可用的结果（package-version格式）
    available_results = get_available_gpt4mini_results_version(gpt4mini_dir)
    
    # 处理 benign
    benign_output = output_base / 'benign'
    benign_stats = process_category(
        packages['benign'],
        available_results['benign'],
        benign_output,
        'BENIGN'
    )
    
    # 处理 malware
    malware_output = output_base / 'malware'
    malware_stats = process_category(
        packages['malware'],
        available_results['malware'],
        malware_output,
        'MALWARE'
    )
    
    all_stats['evaluation'] = {
        'benign': benign_stats,
        'malware': malware_stats
    }
    
    # 打印最终汇总
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print()
    
    for task_name, stats in all_stats.items():
        print(f"{task_name}:")
        print(f"  Benign - Copied: {stats['benign']['copied']}, Not found: {stats['benign']['not_found']}")
        print(f"  Malware - Copied: {stats['malware']['copied']}, Not found: {stats['malware']['not_found']}")
        print()
    
    print("Done!")

if __name__ == '__main__':
    copy_gpt4mini_results()
