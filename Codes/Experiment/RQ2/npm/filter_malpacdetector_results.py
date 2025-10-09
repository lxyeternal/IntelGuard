#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
过滤 MalPacDetector 的结果，只保留在数据集中的包
"""

import os
import csv
from pathlib import Path
from tqdm import tqdm

# 数据集路径
DATASET_BENIGN = '/home2/wenbo/Documents/IntelliGraph/Dataset/NPM/evaluation/zip_benign'
DATASET_MALWARE = '/home2/wenbo/Documents/IntelliGraph/Dataset/NPM/evaluation/zip_malware'

# 输入和输出文件
INPUT_CSV = '/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/results/evaluation/MalPacDetector/summary_detection_results.csv'
OUTPUT_CSV = '/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/results/evaluation/MalPacDetector/filtered_detection_results.csv'


def normalize_package_name(package_name):
    """
    标准化包名，将 @ 和 / 转换为 ##
    """
    # 对于 scoped package，格式为 @scope/name
    # 在文件系统中存储为 @scope##name
    if package_name.startswith('@') and '/' in package_name:
        return package_name.replace('/', '##')
    return package_name


def find_matching_version(package_dir, csv_version):
    """
    在包目录中查找匹配的版本
    
    Args:
        package_dir: 包目录的路径
        csv_version: CSV 中的版本号
    
    Returns:
        如果找到匹配的压缩包，返回压缩包文件名；否则返回 None
    """
    if not os.path.exists(package_dir):
        return None
    
    # 获取目录下所有的 .tgz 文件
    tgz_files = [f for f in os.listdir(package_dir) if f.endswith('.tgz')]
    
    if not tgz_files:
        return None
    
    # 如果只有一个版本，直接返回
    if len(tgz_files) == 1:
        return tgz_files[0]
    
    # 如果有多个版本，查找包含 csv_version 的文件
    for tgz_file in tgz_files:
        # 从文件名中提取版本号（通常格式是 package-name-version.tgz）
        if csv_version in tgz_file:
            return tgz_file
    
    return None


def check_package_exists(package_name, version, package_type):
    """
    检查包是否存在于数据集中
    
    Args:
        package_name: 包名
        version: 版本号
        package_type: benign 或 malware
    
    Returns:
        如果存在返回 True，否则返回 False
    """
    # 根据 package_type 选择数据集路径
    if package_type == 'benign':
        dataset_path = DATASET_BENIGN
    elif package_type == 'malware':
        dataset_path = DATASET_MALWARE
    else:
        return False
    
    # 标准化包名
    normalized_name = normalize_package_name(package_name)
    
    # 构建包目录路径
    package_dir = os.path.join(dataset_path, normalized_name)
    
    # 查找匹配的版本
    matching_file = find_matching_version(package_dir, version)
    
    return matching_file is not None


def filter_csv():
    """
    过滤 CSV 文件，只保留在数据集中的包，并移除 version 列
    """
    print(f"读取输入文件: {INPUT_CSV}")
    
    # 读取 CSV
    with open(INPUT_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    print(f"总共 {len(rows)} 条记录")
    
    # 过滤数据
    filtered_rows = []
    skipped_count = 0
    
    for row in tqdm(rows, desc="过滤数据"):
        package_name = row['package_name']
        version = row['version']
        package_type = row['package_type']
        
        # 检查包是否存在
        if check_package_exists(package_name, version, package_type):
            # 移除 version 列
            filtered_row = {k: v for k, v in row.items() if k != 'version'}
            filtered_rows.append(filtered_row)
        else:
            skipped_count += 1
    
    print(f"保留 {len(filtered_rows)} 条记录")
    print(f"跳过 {skipped_count} 条记录")
    
    # 写入输出文件
    print(f"写入输出文件: {OUTPUT_CSV}")
    
    if filtered_rows:
        # 确保输出目录存在
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        
        with open(OUTPUT_CSV, 'w', encoding='utf-8', newline='') as f:
            # 获取字段名（不包括 version）
            fieldnames = [k for k in rows[0].keys() if k != 'version']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_rows)
        
        print(f"完成！输出文件: {OUTPUT_CSV}")
    else:
        print("警告：没有找到任何匹配的记录！")


if __name__ == '__main__':
    filter_csv()

