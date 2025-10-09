import os
import csv

# File paths
CSV_FILE = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/evaluation/sap/sap_detection_results.csv"
OUTPUT_FILE = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/evaluation/sap/filtered_detection_results.csv"

# Dataset paths for evaluation
BENIGN_DIR = "/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/evaluation/zip_benign"
MALWARE_DIR = "/home2/wenbo/Documents/IntelliGraph/Dataset/PYPI/evaluation/zip_malware"

def check_package_exists(package_name, type_value):
    """
    Check if a package directory exists in the evaluation dataset.
    
    Args:
        package_name: Name of the package
        type_value: The type value (e.g., "evaluation_benign" or "evaluation_malware")
    
    Returns:
        bool: True if package exists, False otherwise
    """
    # Split type to get the label
    if '_' in type_value:
        _, label = type_value.split('_', 1)
    else:
        return False
    
    # Determine which directory to check based on label
    if label == 'benign':
        package_dir = os.path.join(BENIGN_DIR, package_name)
    elif label == 'malware':
        package_dir = os.path.join(MALWARE_DIR, package_name)
    else:
        return False
    
    return os.path.isdir(package_dir)

def filter_csv():
    """
    Filter the CSV file to only include existing packages.
    Split the 'type' column into 'dataset' and 'label' columns.
    """
    total_count = 0
    existing_count = 0
    missing_count = 0
    missing_packages = []
    
    filtered_rows = []
    
    print(f"Reading CSV file: {CSV_FILE}")
    
    with open(CSV_FILE, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)  # Read header
        
        # Modify header: split 'type' into 'dataset' and 'label'
        # Original: Package Name,type,DT,RF,XGB
        # New: Package Name,dataset,label,DT,RF,XGB
        new_header = [header[0], 'dataset', 'label'] + header[2:]
        filtered_rows.append(new_header)
        
        for row in reader:
            if len(row) < 2:
                continue
            
            package_name = row[0]
            type_value = row[1]  # e.g., "evaluation_malware" or "evaluation_benign"
            
            total_count += 1
            
            # Split type into dataset and label
            if '_' in type_value:
                dataset, label = type_value.split('_', 1)
            else:
                dataset = type_value
                label = 'unknown'
            
            # Check if package exists (only for evaluation dataset)
            if dataset == 'evaluation' and check_package_exists(package_name, type_value):
                # Create new row with split columns
                new_row = [package_name, dataset, label] + row[2:]
                filtered_rows.append(new_row)
                existing_count += 1
            elif dataset != 'evaluation':
                # Skip non-evaluation packages
                missing_count += 1
                missing_packages.append((package_name, type_value, "not evaluation dataset"))
            else:
                # Package doesn't exist in dataset
                missing_count += 1
                missing_packages.append((package_name, type_value, "file not found"))
                if missing_count <= 10:
                    print(f"Missing: {package_name} ({type_value})")
    
    # Write filtered results
    print(f"\nWriting filtered results to: {OUTPUT_FILE}")
    with open(OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(filtered_rows)
    
    # Print statistics
    print("\n" + "="*60)
    print("FILTERING STATISTICS")
    print("="*60)
    print(f"Total packages in CSV:     {total_count}")
    print(f"Existing packages:         {existing_count}")
    print(f"Missing packages:          {missing_count}")
    print(f"Percentage kept:           {existing_count/total_count*100:.2f}%")
    print(f"Percentage missing:        {missing_count/total_count*100:.2f}%")
    print("="*60)
    
    if missing_count > 10:
        print(f"\nNote: Only showed first 10 missing packages. Total missing: {missing_count}")
    
    # Save missing packages list
    if missing_packages:
        missing_file = OUTPUT_FILE.replace('.csv', '_missing_packages.txt')
        with open(missing_file, 'w') as f:
            f.write("Missing packages from dataset:\n")
            f.write("="*60 + "\n")
            for pkg, type_val, reason in missing_packages:
                f.write(f"{pkg},{type_val},{reason}\n")
        print(f"\nFull list of missing packages saved to: {missing_file}")

if __name__ == "__main__":
    filter_csv()
    print("\nDone!")

