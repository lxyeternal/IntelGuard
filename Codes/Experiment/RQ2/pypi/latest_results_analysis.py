#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""Accuracy of gpt-4.1-mini on the latest PyPI dataset."""

import os
import json
import glob
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]


def analyze_gpt41(file_path, folder_type):
    """Verdict of a GPT result file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            if data.get("is_malicious", False):
                return "malware"
            else:
                return "benign"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"


def calculate_metrics(true_positives, true_negatives, false_positives, false_negatives):
    """Accuracy, precision, recall and F1."""
    total = true_positives + true_negatives + false_positives + false_negatives
    if total == 0:
        return {
            "accuracy": 0,
            "precision": 0,
            "recall": 0,
            "f1": 0
        }
    
    accuracy = (true_positives + true_negatives) / total
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


def evaluate_file_based_tool(base_path, tool_name, tool_function):
    """Evaluate a tool with one file per package."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "detailed_results": {}
    }
    
    benign_folder = os.path.join(base_path, tool_name, "benign")
    if os.path.exists(benign_folder):
        benign_txt_files = glob.glob(os.path.join(benign_folder, "*.txt"))
        
        print(f"  {len(benign_txt_files)} benign result files")
        
        for file_path in benign_txt_files:
            package_name = os.path.basename(file_path).replace(".txt", "")
            prediction = tool_function(file_path, "benign")
            
            if prediction == "error":
                continue
                
            results["benign_total"] += 1
            
            results["detailed_results"][package_name] = {
                "actual_label": "benign",
                "prediction": prediction,
                "json_path": file_path
            }
            
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    malware_folder = os.path.join(base_path, tool_name, "malware")
    if os.path.exists(malware_folder):
        malware_json_files = glob.glob(os.path.join(malware_folder, "*.json"))
        
        print(f"  {len(malware_json_files)} malware result files")
        
        for file_path in malware_json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            prediction = tool_function(file_path, "malware")
            
            if prediction == "error":
                continue
            
            results["malware_total"] += 1
            
            results["detailed_results"][package_name] = {
                "actual_label": "malware",
                "prediction": prediction,
                "json_path": file_path
            }
            
            if prediction == "malware":
                results["true_positive"] += 1
            elif prediction == "benign":
                results["false_negative"] += 1
                results["misclassified_malware"].append(package_name)
    
    metrics = calculate_metrics(
        results["true_positive"],
        results["true_negative"],
        results["false_positive"],
        results["false_negative"]
    )
    
    results.update(metrics)
    return results


def save_results_to_file(results, output_file):
    """Write the results table."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Latest dataset - gpt-4.1-mini evaluation\n")
        f.write("=" * 80 + "\n\n")
        
        tool_name = "gpt-4.1-mini"
        tool_results = results
        
        total_samples = tool_results["benign_total"] + tool_results["malware_total"]
        false_positive_rate = tool_results["false_positive"] / tool_results["benign_total"] if tool_results["benign_total"] > 0 else 0
        false_negative_rate = tool_results["false_negative"] / tool_results["malware_total"] if tool_results["malware_total"] > 0 else 0
        
        f.write("| Tool | Samples | Accuracy | Precision | Recall | F1 | FP | FN | FPR | FNR |\n")
        f.write("| -------- | -------- | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ |\n")
        f.write(
            f"| {tool_name} | {total_samples} | {tool_results['accuracy']*100:.2f}% | "
            f"{tool_results['precision']*100:.2f}% | {tool_results['recall']*100:.2f}% | {tool_results['f1']*100:.2f}% | "
            f"{tool_results['false_positive']} | {tool_results['false_negative']} | "
            f"{false_positive_rate*100:.2f}% | {false_negative_rate*100:.2f}% |\n"
        )
        
        f.write("\n\nDetails:\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"\n{tool_name}:\n")
        f.write("-" * 40 + "\n")
        f.write(f"Benign samples: {tool_results['benign_total']}\n")
        f.write(f"Malware samples: {tool_results['malware_total']}\n")
        
        f.write(f"TP: {tool_results['true_positive']}\n")
        f.write(f"TN: {tool_results['true_negative']}\n")
        f.write(f"FP: {tool_results['false_positive']}\n")
        f.write(f"FN: {tool_results['false_negative']}\n")
        f.write(f"Accuracy: {tool_results['accuracy']*100:.2f}%\n")
        f.write(f"Precision: {tool_results['precision']*100:.2f}%\n")
        f.write(f"Recall: {tool_results['recall']*100:.2f}%\n")
        f.write(f"F1: {tool_results['f1']*100:.2f}%\n")
        
        f.write(f"FPR: {false_positive_rate*100:.2f}%\n")
        f.write(f"FNR: {false_negative_rate*100:.2f}%\n\n")
        
        if tool_results["misclassified_benign"]:
            f.write("False positives:\n")
            for package in tool_results["misclassified_benign"]:
                f.write(f"- {package}\n")
            f.write("\n")
        
        if tool_results["misclassified_malware"]:
            f.write("False negatives:\n")
            for package in tool_results["misclassified_malware"]:
                f.write(f"- {package}\n")
            f.write("\n")


def main():
    """Entry point."""
    base_path = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/pypi/results/latest"
    tool_name = "gpt-4.1-mini"
    
    print(f"Evaluating {tool_name} on the latest dataset...")
    print(f"Path: {base_path}")
    
    benign_folder = os.path.join(base_path, tool_name, "benign")
    malware_folder = os.path.join(base_path, tool_name, "malware")
    
    benign_count = 0
    benign_py_files = 0
    if os.path.exists(benign_folder):
        benign_txt_files = glob.glob(os.path.join(benign_folder, "*.txt"))
        benign_count = len(benign_txt_files)
        
        print(f"\nCounting benign samples...")
        for txt_file in benign_txt_files[:10]:
            try:
                with open(txt_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    benign_py_files += data.get("files_analyzed", 0)
            except:
                pass
    
    malware_count = 0
    malware_py_files = 0
    if os.path.exists(malware_folder):
        malware_json_files = glob.glob(os.path.join(malware_folder, "*.json"))
        malware_count = len(malware_json_files)
        
        print(f"Counting malware samples...")
        for json_file in malware_json_files[:10]:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    malware_py_files += data.get("files_analyzed", 0)
            except:
                pass
    
    print(f"\nSamples:")
    print(f"  {tool_name}:")
    print(f"    - benign: {benign_count} packages")
    print(f"    - malware: {malware_count} packages")
    print(f"    - total: {benign_count + malware_count} packages")
    
    print(f"\nEvaluating {tool_name}")
    results = evaluate_file_based_tool(base_path, tool_name, analyze_gpt41)
    
    total_samples = results["benign_total"] + results["malware_total"]
    print(
        f"\nResults:")
    print(f"  samples: {total_samples}")
    print(f"  Accuracy: {results['accuracy']*100:.2f}%")
    print(f"  Precision: {results['precision']*100:.2f}%")
    print(f"  Recall: {results['recall']*100:.2f}%")
    print(f"  F1: {results['f1']*100:.2f}%")
    print(f"  TP: {results['true_positive']}")
    print(f"  TN: {results['true_negative']}")
    print(f"  FP: {results['false_positive']}")
    print(f"  FN: {results['false_negative']}")
    
    false_positive_rate = results['false_positive'] / results['benign_total'] if results['benign_total'] > 0 else 0
    false_negative_rate = results['false_negative'] / results['malware_total'] if results['malware_total'] > 0 else 0
    print(f"  FPR: {false_positive_rate*100:.2f}%")
    print(f"  FNR: {false_negative_rate*100:.2f}%")
    
    if results["misclassified_benign"]:
        print(f"\nFalse positives: {len(results['misclassified_benign'])}")
    if results["misclassified_malware"]:
        print(f"False negatives: {len(results['misclassified_malware'])}")
    
    output_file = "latest_gpt41mini_evaluation_results.txt"
    save_results_to_file(results, output_file)
    print(f"\nResults written to: {output_file}")


if __name__ == "__main__":
    main()

