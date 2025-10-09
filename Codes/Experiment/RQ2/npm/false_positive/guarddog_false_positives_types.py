import os
import glob
import re
from collections import defaultdict

def extract_detection_types(file_path):
    """
    从guarddog检测文件中提取检测类型（如obfuscation, code-execution, shady-links等）
    """
    types = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            if "Found 0 potentially malicious indicators" in content or content.strip() == "benign":
                return []
                
            matches = re.findall(r'(\w+(?:-\w+)*): found \d+ source code matches', content)
            types.extend(matches)
            
            other_matches = re.findall(r'(\w+(?:-\w+)*): found \d+ matches', content)
            types.extend(other_matches)
            
            return types
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def main():
    """主函数，分析guarddog假阳性文件的检测类型"""
    base_path = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/results"
    output_file = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/false_positive/guarddog_false_positives_types.txt"
    
    # 可以选择分析哪个数据集: "evaluation" 或 "obfuscation"
    dataset_types = ["evaluation"]
    
    false_positives = []
    type_counts = defaultdict(int)
    files_by_type = defaultdict(list)
    total_benign = 0
    
    for dataset_type in dataset_types:
        benign_folder = os.path.join(base_path, dataset_type, "guarddog", "benign")
        
        if not os.path.exists(benign_folder):
            print(f"警告: 目录不存在 {benign_folder}")
            continue
            
        print(f"开始分析目录: {benign_folder}")
        
        # 遍历每个包文件夹
        for package_name in os.listdir(benign_folder):
            package_folder = os.path.join(benign_folder, package_name)
            
            # 确保是文件夹
            if not os.path.isdir(package_folder):
                continue
                
            # 读取result.txt
            result_file = os.path.join(package_folder, "result.txt")
            if not os.path.exists(result_file):
                continue
                
            total_benign += 1
            types = extract_detection_types(result_file)
            
            if types:
                package_identifier = f"{dataset_type}/{package_name}"
                false_positives.append((package_identifier, types))
                
                for detection_type in types:
                    type_counts[detection_type] += 1
                    files_by_type[detection_type].append(package_identifier)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Guarddog假阳性文件类型统计 (错误地将良性识别为恶意)\n")
        f.write(f"总共找到 {len(false_positives)} 个假阳性 (占良性样本总数 {total_benign} 的 {len(false_positives)/total_benign*100:.2f}%)\n\n")
        
        f.write("检测类型统计：\n")
        f.write("=" * 30 + "\n")
        for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            f.write(f"{detection_type}: {count} 个文件 ({count/len(false_positives)*100:.2f}%)\n")
        
        f.write("\n\n详细分类列表：\n")
        f.write("=" * 30 + "\n")
        for detection_type, packages in sorted(files_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            f.write(f"\n## {detection_type} ({len(packages)} 个包):\n")
            for i, package_identifier in enumerate(sorted(packages), 1):
                f.write(f"{i}. {package_identifier}\n")
        
        f.write("\n\n所有假阳性文件及其检测类型：\n")
        f.write("=" * 30 + "\n")
        for i, (package_identifier, types) in enumerate(sorted(false_positives, key=lambda x: x[0]), 1):
            f.write(f"{i}. {package_identifier}\n")
            f.write(f"   检测类型: {', '.join(types)}\n\n")
    
    print(f"分析完成! 发现 {len(false_positives)} 个假阳性")
    print(f"结果已保存到: {output_file}")

if __name__ == "__main__":
    main() 