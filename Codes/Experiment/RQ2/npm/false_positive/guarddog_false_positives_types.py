"""Detection types of guarddog false positives."""
import os
import glob
import re
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[5]

def extract_detection_types(file_path):
    """Detection types in a guarddog result file."""
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
    """Entry point."""
    base_path = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results"
    output_file = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/false_positive/guarddog_false_positives_types.txt"
    
    dataset_types = ["evaluation"]
    
    false_positives = []
    type_counts = defaultdict(int)
    files_by_type = defaultdict(list)
    total_benign = 0
    
    for dataset_type in dataset_types:
        benign_folder = os.path.join(base_path, dataset_type, "guarddog", "benign")
        
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
                
            total_benign += 1
            types = extract_detection_types(result_file)
            
            if types:
                package_identifier = f"{dataset_type}/{package_name}"
                false_positives.append((package_identifier, types))
                
                for detection_type in types:
                    type_counts[detection_type] += 1
                    files_by_type[detection_type].append(package_identifier)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Guarddog false positive types (benign flagged as malicious)\n")
        f.write(f"{len(false_positives)} false positives out of {total_benign} benign packages ({len(false_positives)/total_benign*100:.2f}%)\n\n")
        
        f.write("Detection types:\n")
        f.write("=" * 30 + "\n")
        for detection_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            f.write(f"{detection_type}: {count} files ({count/len(false_positives)*100:.2f}%)\n")
        
        f.write("\n\nPackages per type:\n")
        f.write("=" * 30 + "\n")
        for detection_type, packages in sorted(files_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            f.write(f"\n## {detection_type} ({len(packages)} packages):\n")
            for i, package_identifier in enumerate(sorted(packages), 1):
                f.write(f"{i}. {package_identifier}\n")
        
        f.write("\n\nAll false positives and their detection types:\n")
        f.write("=" * 30 + "\n")
        for i, (package_identifier, types) in enumerate(sorted(false_positives, key=lambda x: x[0]), 1):
            f.write(f"{i}. {package_identifier}\n")
            f.write(f"   types: {', '.join(types)}\n\n")
    
    print(f"Done: {len(false_positives)} false positives")
    print(f"Results written to: {output_file}")

if __name__ == "__main__":
    main() 
