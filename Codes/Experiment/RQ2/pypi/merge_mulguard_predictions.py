"""
合并 MulGuard 预测结果并过滤存在的包 (通用版本)
"""
import csv
import sys
from pathlib import Path


def merge_and_filter(dataset_type):
    """
    合并并过滤预测结果
    
    Args:
        dataset_type: 数据集类型，可选 'evaluation' 或 'obfuscation'
    """
    # 输入文件路径
    benign_csv = Path(f"/home2/wenbo/Documents/PyPIAgent/Tools/MulGuard/TestData/{dataset_type}/predictions_benign.csv")
    malware_csv = Path(f"/home2/wenbo/Documents/PyPIAgent/Tools/MulGuard/TestData/{dataset_type}/predictions_malware.csv")
    
    # 输出目录和文件
    output_dir = Path(f"/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/{dataset_type}/MulGuard")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "predictions.csv"
    
    # 验证包存在的目录
    benign_zip_dir = Path(f"/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/{dataset_type}/zip_benign")
    malware_zip_dir = Path(f"/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/{dataset_type}/zip_malware")
    
    # 获取所有存在的包名
    valid_packages = set()
    
    print(f"{'='*60}")
    print(f"处理数据集: {dataset_type}")
    print(f"{'='*60}")
    
    print("\n正在扫描 benign 包...")
    if benign_zip_dir.exists():
        for item in benign_zip_dir.iterdir():
            if item.is_dir():
                valid_packages.add(item.name)
    print(f"找到 {len(valid_packages)} 个 benign 包")
    
    print("正在扫描 malware 包...")
    malware_count = 0
    if malware_zip_dir.exists():
        for item in malware_zip_dir.iterdir():
            if item.is_dir():
                valid_packages.add(item.name)
                malware_count += 1
    print(f"找到 {malware_count} 个 malware 包")
    print(f"总共有效包: {len(valid_packages)}")
    
    # 读取并合并CSV
    all_rows = []
    headers = None
    
    print("\n正在读取 benign 预测...")
    with open(benign_csv, 'r') as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        for row in reader:
            package_name = row['package_name']
            if package_name in valid_packages:
                all_rows.append(row)
    print(f"保留 {len(all_rows)} 条 benign 记录")
    
    print("正在读取 malware 预测...")
    malware_kept = 0
    with open(malware_csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            package_name = row['package_name']
            if package_name in valid_packages:
                all_rows.append(row)
                malware_kept += 1
    print(f"保留 {malware_kept} 条 malware 记录")
    
    # 写入合并后的CSV
    print(f"\n正在写入合并结果到: {output_file}")
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(all_rows)
    
    print(f"\n完成！")
    print(f"总共保留 {len(all_rows)} 条记录")
    print(f"输出文件: {output_file}")
    print()


def main():
    # 如果提供了命令行参数，只处理指定的数据集
    if len(sys.argv) > 1:
        dataset_type = sys.argv[1]
        if dataset_type not in ['evaluation', 'obfuscation']:
            print(f"错误: 未知的数据集类型 '{dataset_type}'")
            print("用法: python merge_and_filter_predictions_unified.py [evaluation|obfuscation]")
            sys.exit(1)
        merge_and_filter(dataset_type)
    else:
        # 没有参数时，处理所有数据集
        merge_and_filter('evaluation')
        merge_and_filter('obfuscation')


if __name__ == "__main__":
    main()

