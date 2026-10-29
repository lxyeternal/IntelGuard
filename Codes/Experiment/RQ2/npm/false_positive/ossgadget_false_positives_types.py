"""Detection types of ossgadget false positives."""
import os
import re
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[5]

def extract_detection_types(file_path):
    """Detection types in an ossgadget result file."""
    detection_types = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            tags = re.findall(r'Tag: \x1B\[34m(.*?)\x1B\[0m', content)
            
            for tag in tags:
                detection_types.add(tag)
                
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        
    return detection_types

def main():
    """Entry point."""
    base_path = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results"
    output_file = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/false_positive/ossgadget_false_positives_types.txt"
    
    dataset_types = ["evaluation"]
    
    type_to_files = defaultdict(list)
    type_counts = defaultdict(int)
    total_files = 0
    files_with_detections = 0
    
    for dataset_type in dataset_types:
        benign_folder = os.path.join(base_path, dataset_type, "ossgadget", "benign")
        
        if not os.path.exists(benign_folder):
            print(f"Warning: directory not found {benign_folder}")
            continue
            
        print(f"Analyzing directory: {benign_folder}")
        
        for package_name in os.listdir(benign_folder):
            package_folder = os.path.join(benign_folder, package_name)
            
            if not os.path.isdir(package_folder):
                continue
                
            result_file = os.path.join(package_folder, "result.txt")
            if not os.path.exists(result_file):
                continue
                
            total_files += 1
            detection_types = extract_detection_types(result_file)
            
            if detection_types:
                files_with_detections += 1
                for detection_type in detection_types:
                    package_identifier = f"{dataset_type}/{package_name}"
                    type_to_files[detection_type].append(package_identifier)
                    type_counts[detection_type] += 1
                
            if total_files % 100 == 0:
                print(f"{total_files} files processed...")
    
    print(f"\nDone: {total_files} files processed")
    print(f"{files_with_detections} files with false positives")
    print(f"{len(type_counts)} detection types")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("OSSGadget false positive types\n")
        f.write("=" * 50 + "\n\n")
        
        f.write(f"Benign files analyzed: {total_files}\n")
        f.write(f"Files with false positives: {files_with_detections} ({(files_with_detections/total_files)*100:.2f}%)\n\n")
        
        f.write("False positives per type:\n")
        f.write("-" * 30 + "\n")
        for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / files_with_detections) * 100 if files_with_detections > 0 else 0
            f.write(f"{detection_type}: {count} files ({percentage:.2f}%)\n")
        
        f.write("\nFiles per type:\n")
        f.write("=" * 50 + "\n\n")
        for detection_type, packages in sorted(type_to_files.items(), key=lambda x: len(x[1]), reverse=True):
            f.write(f"\n{detection_type}:\n")
            f.write("-" * 30 + "\n")
            for package_identifier in packages:
                f.write(f"{package_identifier}\n")
            f.write(f"{len(packages)} packages\n")
    
    print(f"Results written to: {output_file}")

if __name__ == "__main__":
    main()
