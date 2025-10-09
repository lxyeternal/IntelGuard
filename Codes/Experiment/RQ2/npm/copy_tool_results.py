#!/usr/bin/env python3
"""
复制各工具的检测结果到对应的数据集结构中（NPM版本）
处理版本匹配逻辑：从 包名/版本/文件 结构转换为 包名/文件 结构
"""

import os
import shutil
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

# 数据集路径
DATASET_PATH = '/home2/wenbo/Documents/IntelliGraph/Dataset/NPM/evaluation'

# 工具结果路径
TOOL_RESULTS = {
    'guarddog': '/home2/wenbo/Documents/NPMAnalysis/Codes/tool_detect/tool_output/guarddog',
    'ossgadget': '/home2/wenbo/Documents/NPMAnalysis/Codes/tool_detect/tool_output/ossgadget',
    'socketai': '/home2/wenbo/Documents/NPMAnalysis/Codes/tool_detect/tool_output/socketai',
    'genie': '/home2/wenbo/Documents/NPMAnalysis/Codes/tool_detect/tool_output/genie',
    # packj 特殊处理，有 result_static 和 result_trace 两个子目录
}

PACKJ_RESULTS = {
    'packj_static': '/home2/wenbo/Documents/NPMAnalysis/Codes/tool_detect/tool_output/packj/result_static',
    'packj_trace': '/home2/wenbo/Documents/NPMAnalysis/Codes/tool_detect/tool_output/packj/result_trace',
}

# 目标路径
TARGET_BASE = '/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/results/evaluation'


def get_package_info(dataset_path):
    """
    从数据集中获取所有包名及其版本信息
    返回: {
        'benign': {包名: [压缩包文件名列表]},
        'malware': {包名: [压缩包文件名列表]}
    }
    """
    packages = {'benign': {}, 'malware': {}}
    
    for label in ['benign', 'malware']:
        label_path = Path(dataset_path) / f'zip_{label}'
        if not label_path.exists():
            print(f"Warning: {label_path} does not exist!")
            continue
        
        # 遍历包名文件夹
        for pkg_dir in os.listdir(label_path):
            pkg_path = label_path / pkg_dir
            if not pkg_path.is_dir():
                continue
            
            # 获取该包下的所有压缩包文件
            archives = []
            for item in os.listdir(pkg_path):
                if item.endswith('.tgz') or item.endswith('.tar.gz'):
                    archives.append(item)
            
            if archives:
                packages[label][pkg_dir] = archives
        
        print(f"Found {len(packages[label])} {label} packages in dataset")
    
    return packages


def extract_version_from_archive(archive_name):
    """
    从压缩包文件名中提取版本号
    例如: @99xt##first-born-1.1.8.tgz -> 1.1.8
    """
    # 移除扩展名
    name = archive_name.replace('.tgz', '').replace('.tar.gz', '')
    
    # 尝试提取版本号（通常是最后一段，以数字开头）
    parts = name.split('-')
    for i in range(len(parts) - 1, -1, -1):
        part = parts[i]
        # 检查是否以数字开头（版本号特征）
        if part and part[0].isdigit():
            # 重新组合可能的版本号（可能包含多个-分隔的部分）
            return '-'.join(parts[i:])
    
    return None


def match_version(version_dir_name, archive_names):
    """
    检查版本目录名是否匹配任何一个压缩包文件名
    
    Args:
        version_dir_name: 版本文件夹名称（如 3.25.4-theta）
        archive_names: 压缩包文件名列表
    
    Returns:
        True if matched, False otherwise
    """
    for archive in archive_names:
        if version_dir_name in archive:
            return True
    return False


def copy_result_files(src_dir, dst_dir):
    """
    复制目录下的所有文件到目标目录
    
    Args:
        src_dir: 源目录（版本文件夹）
        dst_dir: 目标目录（包名文件夹）
    
    Returns:
        (success, file_count, error_msg)
    """
    try:
        # 确保目标目录存在
        dst_dir.mkdir(parents=True, exist_ok=True)
        
        # 复制所有文件
        file_count = 0
        for item in os.listdir(src_dir):
            src_file = src_dir / item
            if src_file.is_file():
                dst_file = dst_dir / item
                shutil.copy2(src_file, dst_file)
                file_count += 1
        
        return (True, file_count, None)
    except Exception as e:
        return (False, 0, str(e))


def process_single_package(args):
    """
    处理单个包的复制（用于并行处理）
    
    Args:
        args: (pkg_name, tool_result_path, target_path, archive_names)
    
    Returns:
        (pkg_name, status_dict)
    """
    pkg_name, tool_result_path, target_path, archive_names = args
    
    status = {
        'found': False,
        'copied': False,
        'files': 0,
        'versions': [],
        'error': None
    }
    
    try:
        pkg_result_path = tool_result_path / pkg_name
        if not pkg_result_path.exists():
            return (pkg_name, status)
        
        status['found'] = True
        
        # 获取所有版本目录
        version_dirs = [d for d in os.listdir(pkg_result_path) 
                       if (pkg_result_path / d).is_dir()]
        
        if not version_dirs:
            # 没有版本目录，可能直接就是文件
            success, file_count, error = copy_result_files(pkg_result_path, target_path)
            if success:
                status['copied'] = True
                status['files'] = file_count
            else:
                status['error'] = error
            return (pkg_name, status)
        
        # 如果只有一个版本，直接复制
        if len(version_dirs) == 1:
            version_dir = pkg_result_path / version_dirs[0]
            success, file_count, error = copy_result_files(version_dir, target_path)
            if success:
                status['copied'] = True
                status['files'] = file_count
                status['versions'].append(version_dirs[0])
            else:
                status['error'] = error
        else:
            # 多个版本，需要匹配
            matched = False
            for version_name in version_dirs:
                if match_version(version_name, archive_names):
                    version_dir = pkg_result_path / version_name
                    success, file_count, error = copy_result_files(version_dir, target_path)
                    if success:
                        status['copied'] = True
                        status['files'] = file_count
                        status['versions'].append(version_name)
                        matched = True
                        break  # 只复制第一个匹配的版本
                    else:
                        status['error'] = error
                        break
            
            if not matched:
                status['error'] = f"Multiple versions found but none matched: {version_dirs}"
        
    except Exception as e:
        status['error'] = str(e)
    
    return (pkg_name, status)


def copy_tool_results(tool_name, tool_result_base, packages, max_workers=8):
    """
    复制工具结果（并行版本）
    
    Args:
        tool_name: 工具名称（用于目标路径）
        tool_result_base: 工具结果基础路径
        packages: 包信息字典
        max_workers: 并行工作进程数
    
    Returns:
        统计信息字典
    """
    print(f"\n{'='*80}")
    print(f"Processing: {tool_name}")
    print(f"Source: {tool_result_base}")
    print(f"{'='*80}\n")
    
    tool_result_path = Path(tool_result_base)
    target_base = Path(TARGET_BASE) / tool_name
    
    stats = {
        'benign': {'found': 0, 'copied': 0, 'not_found': 0, 'errors': []},
        'malware': {'found': 0, 'copied': 0, 'not_found': 0, 'errors': []}
    }
    
    for label in ['benign', 'malware']:
        tool_label_path = tool_result_path / label
        target_label_path = target_base / label
        
        if not tool_label_path.exists():
            print(f"Warning: {tool_label_path} does not exist!")
            continue
        
        print(f"\n{label.upper()}: Processing {len(packages[label])} packages")
        
        # 准备处理任务
        tasks = []
        for pkg_name, archive_names in packages[label].items():
            target_pkg_path = target_label_path / pkg_name
            tasks.append((pkg_name, tool_label_path, target_pkg_path, archive_names))
        
        print(f"Processing {len(tasks)} packages using {max_workers} workers...")
        
        # 并行处理
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_single_package, task): task for task in tasks}
            
            with tqdm(total=len(tasks), desc=f"{label.upper()}", unit="pkg") as pbar:
                for future in as_completed(futures):
                    pkg_name, status = future.result()
                    
                    if status['found']:
                        stats[label]['found'] += 1
                        if status['copied']:
                            stats[label]['copied'] += 1
                        elif status['error']:
                            stats[label]['errors'].append((pkg_name, status['error']))
                    else:
                        stats[label]['not_found'] += 1
                    
                    pbar.update(1)
        
        # 打印统计
        print(f"\n{label.upper()} Summary:")
        print(f"  - Found in tool results: {stats[label]['found']}")
        print(f"  - Successfully copied: {stats[label]['copied']}")
        print(f"  - Not found: {stats[label]['not_found']}")
        print(f"  - Errors: {len(stats[label]['errors'])}")
        
        if stats[label]['errors'] and len(stats[label]['errors']) <= 10:
            print(f"  Error examples (first 10):")
            for pkg_name, error in stats[label]['errors'][:10]:
                print(f"    - {pkg_name}: {error}")
    
    return stats


def main():
    """主函数"""
    print("Starting to copy NPM tool results...\n")
    print(f"Dataset path: {DATASET_PATH}")
    print(f"Target base: {TARGET_BASE}\n")
    
    # 获取数据集包信息
    print("Scanning dataset...")
    packages = get_package_info(DATASET_PATH)
    
    total_stats = {}
    
    # 处理常规工具（guarddog, ossgadget, socketai）
    for tool_name, tool_path in TOOL_RESULTS.items():
        total_stats[tool_name] = copy_tool_results(tool_name, tool_path, packages)
    
    # 处理 packj（有两个子目录）
    for packj_variant, packj_path in PACKJ_RESULTS.items():
        total_stats[packj_variant] = copy_tool_results(packj_variant, packj_path, packages)
    
    # 打印总结
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}\n")
    
    for tool_name, stats in total_stats.items():
        print(f"{tool_name}:")
        for label in ['benign', 'malware']:
            print(f"  {label.capitalize()}: "
                  f"{stats[label]['copied']} copied, "
                  f"{stats[label]['not_found']} not found, "
                  f"{len(stats[label]['errors'])} errors")
        print()


if __name__ == '__main__':
    main()

