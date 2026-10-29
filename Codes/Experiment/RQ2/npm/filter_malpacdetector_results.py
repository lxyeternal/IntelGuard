#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Keep only the MalPacDetector rows whose package is in the dataset."""

import os
import csv
from pathlib import Path
from tqdm import tqdm

PROJECT_ROOT = Path(__file__).resolve().parents[4]

DATASET_BENIGN = f'{PROJECT_ROOT}/Dataset/NPM/evaluation/zip_benign'
DATASET_MALWARE = f'{PROJECT_ROOT}/Dataset/NPM/evaluation/zip_malware'

INPUT_CSV = f'{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results/evaluation/MalPacDetector/summary_detection_results.csv'
OUTPUT_CSV = f'{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results/evaluation/MalPacDetector/filtered_detection_results.csv'


def normalize_package_name(package_name):
    """Package name as used in the dataset folders."""
    if package_name.startswith('@') and '/' in package_name:
        return package_name.replace('/', '##')
    return package_name


def find_matching_version(package_dir, csv_version):
    """Archive matching a version, or None."""
    if not os.path.exists(package_dir):
        return None
    
    tgz_files = [f for f in os.listdir(package_dir) if f.endswith('.tgz')]
    
    if not tgz_files:
        return None
    
    if len(tgz_files) == 1:
        return tgz_files[0]
    
    for tgz_file in tgz_files:
        if csv_version in tgz_file:
            return tgz_file
    
    return None


def check_package_exists(package_name, version, package_type):
    """Whether a package version is in the dataset."""
    if package_type == 'benign':
        dataset_path = DATASET_BENIGN
    elif package_type == 'malware':
        dataset_path = DATASET_MALWARE
    else:
        return False
    
    normalized_name = normalize_package_name(package_name)
    
    package_dir = os.path.join(dataset_path, normalized_name)
    
    matching_file = find_matching_version(package_dir, version)
    
    return matching_file is not None


def filter_csv():
    """Filter the CSV."""
    print(f"Reading {INPUT_CSV}")
    
    with open(INPUT_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    print(f"{len(rows)} rows")
    
    filtered_rows = []
    skipped_count = 0
    
    for row in tqdm(rows, desc="filtering"):
        package_name = row['package_name']
        version = row['version']
        package_type = row['package_type']
        
        if check_package_exists(package_name, version, package_type):
            filtered_row = {k: v for k, v in row.items() if k != 'version'}
            filtered_rows.append(filtered_row)
        else:
            skipped_count += 1
    
    print(f"Kept {len(filtered_rows)} rows")
    print(f"Dropped {skipped_count} rows")
    
    print(f"Writing {OUTPUT_CSV}")
    
    if filtered_rows:
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        
        with open(OUTPUT_CSV, 'w', encoding='utf-8', newline='') as f:
            fieldnames = [k for k in rows[0].keys() if k != 'version']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_rows)
        
        print(f"Done: {OUTPUT_CSV}")
    else:
        print("Warning: no matching rows")


if __name__ == '__main__':
    filter_csv()

