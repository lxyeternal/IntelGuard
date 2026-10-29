"""Merge the MulGuard predictions and keep the packages in the dataset."""
import csv
import sys
from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parents[4]


def merge_and_filter(dataset_type):
    """Merge the benign and malware predictions of one dataset."""
    benign_csv = Path(os.environ.get("MULGUARD_TESTDATA", "MulGuard/TestData")) / dataset_type / "predictions_benign.csv"
    malware_csv = Path(os.environ.get("MULGUARD_TESTDATA", "MulGuard/TestData")) / dataset_type / "predictions_malware.csv"
    
    output_dir = Path(f"{PROJECT_ROOT}/Codes/Experiment/RQ2/pypi/results/{dataset_type}/MulGuard")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "predictions.csv"
    
    benign_zip_dir = Path(f"{PROJECT_ROOT}/Dataset/PYPI/{dataset_type}/zip_benign")
    malware_zip_dir = Path(f"{PROJECT_ROOT}/Dataset/PYPI/{dataset_type}/zip_malware")
    
    valid_packages = set()
    
    print(f"{'='*60}")
    print(f"Dataset: {dataset_type}")
    print(f"{'='*60}")
    
    print("\nScanning benign packages...")
    if benign_zip_dir.exists():
        for item in benign_zip_dir.iterdir():
            if item.is_dir():
                valid_packages.add(item.name)
    print(f"{len(valid_packages)} benign packages")
    
    print("Scanning malware packages...")
    malware_count = 0
    if malware_zip_dir.exists():
        for item in malware_zip_dir.iterdir():
            if item.is_dir():
                valid_packages.add(item.name)
                malware_count += 1
    print(f"{malware_count} malware packages")
    print(f"Valid packages: {len(valid_packages)}")
    
    all_rows = []
    headers = None
    
    print("\nReading benign predictions...")
    with open(benign_csv, 'r') as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        for row in reader:
            package_name = row['package_name']
            if package_name in valid_packages:
                all_rows.append(row)
    print(f"Kept {len(all_rows)} benign rows")
    
    print("Reading malware predictions...")
    malware_kept = 0
    with open(malware_csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            package_name = row['package_name']
            if package_name in valid_packages:
                all_rows.append(row)
                malware_kept += 1
    print(f"Kept {malware_kept} malware rows")
    
    print(f"\nWriting {output_file}")
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(all_rows)
    
    print(f"\nDone")
    print(f"{len(all_rows)} rows kept")
    print(f"Output: {output_file}")
    print()


def main():
    """Entry point."""
    if len(sys.argv) > 1:
        dataset_type = sys.argv[1]
        if dataset_type not in ['evaluation', 'obfuscation']:
            print(f"Error: unknown dataset type '{dataset_type}'")
            print("Usage: python merge_mulguard_predictions.py [evaluation|obfuscation]")
            sys.exit(1)
        merge_and_filter(dataset_type)
    else:
        merge_and_filter('evaluation')
        merge_and_filter('obfuscation')


if __name__ == "__main__":
    main()

