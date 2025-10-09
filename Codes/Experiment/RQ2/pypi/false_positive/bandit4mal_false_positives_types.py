import os
import re
from collections import defaultdict

def extract_detection_types(file_path):
    """提取bandit4mal检测文件中的检测类型"""
    detection_types = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            issues = re.findall(r'>> Issue: \[(.*?)\]', content)
            
            for issue in issues:
                detection_types.add(issue)
                
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {str(e)}")
        
    return detection_types

def main():
    base_path = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results"
    output_file = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/false_positive/bandit4mal_false_positives_types.txt"
    
    # 可以选择分析哪个数据集: "evaluation" 或 "obfuscation"
    dataset_types = ["obfuscation"]
    
    type_to_files = defaultdict(list)
    type_counts = defaultdict(int)
    total_files = 0
    files_with_detections = 0
    
    for dataset_type in dataset_types:
        benign_folder = os.path.join(base_path, dataset_type, "bandit4mal", "benign")
        
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
                
            total_files += 1
            detection_types = extract_detection_types(result_file)
            
            if detection_types:
                files_with_detections += 1
                for detection_type in detection_types:
                    type_to_files[detection_type].append(f"{dataset_type}/{package_name}")
                    type_counts[detection_type] += 1
                    
            if total_files % 100 == 0:
                print(f"已处理 {total_files} 个文件...")
    
    print(f"\n分析完成，共处理 {total_files} 个文件")
    print(f"发现 {files_with_detections} 个文件含有误报")
    print(f"发现 {len(type_counts)} 种不同的检测类型")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Bandit4mal误报类型统计\n")
        f.write("=" * 50 + "\n\n")
        
        f.write(f"总共分析的良性样本文件数: {total_files}\n")
        f.write(f"含有误报的文件数: {files_with_detections} ({(files_with_detections/total_files)*100:.2f}%)\n\n")
        
        f.write("各类型误报统计:\n")
        f.write("-" * 30 + "\n")
        for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / files_with_detections) * 100 if files_with_detections > 0 else 0
            f.write(f"{detection_type}: {count} 个文件 ({percentage:.2f}%)\n")
        
        f.write("\n详细文件列表:\n")
        f.write("=" * 50 + "\n\n")
        for detection_type, packages in sorted(type_to_files.items()):
            f.write(f"\n{detection_type}类型的包:\n")
            f.write("-" * 30 + "\n")
            for package_identifier in packages:
                f.write(f"{package_identifier}\n")
            f.write(f"共 {len(packages)} 个包\n")
    
    print(f"结果已保存到: {output_file}")

if __name__ == "__main__":
    main() 