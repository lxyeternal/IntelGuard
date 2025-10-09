#!/usr/bin/env python3
"""
清理数据集脚本
读取 no_maliicous.txt 中的包名，在 obfuscation 和 regular 数据集中删除对应的包
确保 zip 和 unzip 文件夹同步删除
"""

import os
import re
import shutil
from pathlib import Path

def parse_package_names(txt_file):
    """解析 txt 文件，提取所有包名（不做任何解析，直接使用原始内容）"""
    package_names = set()
    
    with open(txt_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        
        # 只跳过空行
        if not line:
            continue
        
        # 直接添加包名
        package_names.add(line)
    
    return package_names

def find_matching_packages(base_dir, package_names):
    """在指定目录中查找匹配的包（完全匹配包名）"""
    matched_packages = {
        'zip_malware': [],
        'zip_benign': [],
        'unzip_malware': [],
        'unzip_benign': []
    }
    
    for folder in ['zip_malware', 'zip_benign', 'unzip_malware', 'unzip_benign']:
        folder_path = os.path.join(base_dir, folder)
        if not os.path.exists(folder_path):
            continue
        
        try:
            items = os.listdir(folder_path)
        except PermissionError:
            print(f"权限错误：无法访问 {folder_path}")
            continue
        
        for item in items:
            # 直接检查是否完全匹配包名
            if item in package_names:
                matched_packages[folder].append(item)
    
    return matched_packages

def delete_package(base_dir, folder, package_name):
    """删除指定文件夹中的包"""
    package_path = os.path.join(base_dir, folder, package_name)
    
    if os.path.exists(package_path):
        try:
            if os.path.isdir(package_path):
                shutil.rmtree(package_path)
            else:
                os.remove(package_path)
            print(f"  ✓ 删除 {folder}/{package_name}")
            return True
        except Exception as e:
            print(f"  ✗ 删除失败 {folder}/{package_name}: {e}")
            return False
    return False

def main():
    # 配置路径
    txt_file = '/home2/wenbo/Documents/IntelliGraph/Codes/Dataclean/no_maliicous.txt'
    datasets = [
        '/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/obfuscation',
        '/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/regular'
    ]
    
    print("=" * 70)
    print("开始清理数据集")
    print("=" * 70)
    
    # 解析包名
    print(f"\n正在解析 {txt_file} ...")
    package_names = parse_package_names(txt_file)
    print(f"找到 {len(package_names)} 个包名")
    
    # 处理每个数据集
    total_deleted = 0
    for dataset_path in datasets:
        if not os.path.exists(dataset_path):
            print(f"\n警告: 数据集路径不存在: {dataset_path}")
            continue
        
        print(f"\n{'=' * 70}")
        print(f"处理数据集: {os.path.basename(dataset_path)}")
        print(f"{'=' * 70}")
        
        # 查找匹配的包
        matched = find_matching_packages(dataset_path, package_names)
        
        # 统计匹配数量
        malware_count = len(matched['zip_malware'])
        benign_count = len(matched['zip_benign'])
        
        print(f"\n找到匹配的包:")
        print(f"  - malware: {malware_count} 个")
        print(f"  - benign: {benign_count} 个")
        
        # 删除所有匹配的包
        print(f"\n开始删除匹配的包:")
        for folder in ['zip_malware', 'zip_benign', 'unzip_malware', 'unzip_benign']:
            if matched[folder]:
                print(f"\n{folder}:")
                for pkg in matched[folder]:
                    if delete_package(dataset_path, folder, pkg):
                        total_deleted += 1
    
    print(f"\n{'=' * 70}")
    print(f"清理完成! 共处理 {total_deleted} 个包")
    print(f"{'=' * 70}")

if __name__ == '__main__':
    main()
