"""Accuracy of the baseline tools on the npm dataset."""
import os
import json
import glob
import csv
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]

EXCLUDED_MALWARE_PACKAGES = {
    "seller-journey",
    "frontend-libraries",
    "sofa1-shop",
    "serverless-provisioned-memory-report",
    "snyk-vulnerability-scanner",
    "immutable-seaport"
}

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

def analyze_guarddog(file_path, folder_type):
    """Verdict of a guarddog result file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "Found 0 potentially malicious indicators" in content:
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"

def analyze_ossgadget(file_path, folder_type):
    """Verdict of an ossgadget result file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "0 matches found." in content:
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"

def analyze_packj(file_path, folder_type):
    """Verdict of a packj result file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if not content.strip() or "No risks found!" in content:
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"

def analyze_genie(file_path, folder_type):
    """Verdict of a genie result file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if not content.strip():
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return "error"

def analyze_json_tool(file_path, folder_type):
    """Verdict of a JSON result file."""
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

def analyze_socketai(package_folder_path, folder_type):
    """Verdict of a socketai package folder."""
    try:
        json_file_path = os.path.join(package_folder_path, "package_summary.txt")
        
        if not os.path.exists(json_file_path):
            print(f"Warning: package_summary.txt not found at {json_file_path}")
            return "error"
        
        with open(json_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            if data.get("is_malicious", False):
                return "malware"
            else:
                return "benign"
    except Exception as e:
        print(f"Error reading socketai result from {package_folder_path}: {e}")
        return "error"

def analyze_sap_models(csv_file_path):
    """Per-model verdicts from the SAP CSV."""
    sap_results = {"dt": {}, "rf": {}, "xgb": {}}

    try:
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                package_name = row['Package Name']
                type_info = row['type']
                
                actual_label = type_info
                
                if actual_label == "malware" and package_name in EXCLUDED_MALWARE_PACKAGES:
                    continue
                
                for model in ['dt', 'rf', 'xgb']:
                    model_key = model.upper()
                    prediction = int(row[model_key]) if model_key in row else 0
                    
                    result = "malware" if prediction == 1 else "benign"
                    
                    if actual_label not in sap_results[model]:
                        sap_results[model][actual_label] = {}
                    
                    sap_results[model][actual_label][package_name] = result
        
        return sap_results
    except Exception as e:
        print(f"Error reading SAP CSV file {csv_file_path}: {e}")
        return None

def analyze_malpacdetector_models(csv_file_path):
    """Per-model verdicts from the MalPacDetector CSV."""
    malpac_results = {"mlp": {}, "nb": {}, "svm": {}}

    try:
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                package_name = row['package_name']
                actual_label = row['actual_label']
                
                if actual_label == "malware" and package_name in EXCLUDED_MALWARE_PACKAGES:
                    continue
                
                for model in ['mlp', 'nb', 'svm']:
                    model_key = model.upper()
                    prediction = row[model_key].strip() if model_key in row else "benign"
                    
                    if prediction == "malicious":
                        result = "malware"
                    else:
                        result = "benign"
                    
                    if actual_label not in malpac_results[model]:
                        malpac_results[model][actual_label] = {}
                    
                    malpac_results[model][actual_label][package_name] = result
        
        return malpac_results
    except Exception as e:
        print(f"Error reading MalPacDetector CSV file {csv_file_path}: {e}")
        return None

def evaluate_folder_based_tool(base_path, tool_name, tool_function):
    """Evaluate a tool with one folder per package."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "errors": 0
    }
    
    benign_folder = os.path.join(base_path, tool_name, "benign")
    if os.path.exists(benign_folder):
        package_folders = [d for d in os.listdir(benign_folder) 
                          if os.path.isdir(os.path.join(benign_folder, d))]
        
        for package_name in package_folders:
            package_folder_path = os.path.join(benign_folder, package_name)
            
            if tool_name == "guarddog":
                file_path = os.path.join(package_folder_path, "result.txt")
            elif tool_name == "ossgadget":
                file_path = os.path.join(package_folder_path, "result.txt")
            elif tool_name == "packj_trace":
                file_path = os.path.join(package_folder_path, "result.txt")
            elif tool_name == "packj_static":
                txt_files = glob.glob(os.path.join(package_folder_path, "*.txt"))
                if not txt_files:
                    continue
                file_path = txt_files[0]
            elif tool_name == "genie":
                csv_files = glob.glob(os.path.join(package_folder_path, "*.csv"))
                if not csv_files:
                    continue
                file_path = csv_files[0]
            else:
                continue
            
            if not os.path.exists(file_path):
                continue
            
            prediction = tool_function(file_path, "benign")
            if prediction == "error":
                results["errors"] += 1
                continue
            
            results["benign_total"] += 1
            
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    malware_folder = os.path.join(base_path, tool_name, "malware")
    if os.path.exists(malware_folder):
        package_folders = [d for d in os.listdir(malware_folder) 
                          if os.path.isdir(os.path.join(malware_folder, d))]
        
        for package_name in package_folders:
            if package_name in EXCLUDED_MALWARE_PACKAGES:
                continue
            
            package_folder_path = os.path.join(malware_folder, package_name)
            
            if tool_name == "guarddog":
                file_path = os.path.join(package_folder_path, "result.txt")
            elif tool_name == "ossgadget":
                file_path = os.path.join(package_folder_path, "result.txt")
            elif tool_name == "packj_trace":
                file_path = os.path.join(package_folder_path, "result.txt")
            elif tool_name == "packj_static":
                txt_files = glob.glob(os.path.join(package_folder_path, "*.txt"))
                if not txt_files:
                    continue
                file_path = txt_files[0]
            elif tool_name == "genie":
                csv_files = glob.glob(os.path.join(package_folder_path, "*.csv"))
                if not csv_files:
                    continue
                file_path = csv_files[0]
            else:
                continue
            
            if not os.path.exists(file_path):
                continue
            
            prediction = tool_function(file_path, "malware")
            if prediction == "error":
                results["errors"] += 1
                continue
            
            results["malware_total"] += 1
            
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

def evaluate_json_tool(base_path, tool_name):
    """Evaluate a tool with one JSON file per package."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "errors": 0,
        "detailed_results": {}
    }
    
    benign_folder = os.path.join(base_path, tool_name, "benign")
    if os.path.exists(benign_folder):
        json_files = glob.glob(os.path.join(benign_folder, "*.json"))
        
        for file_path in json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            if package_name.endswith("-result"):
                package_name = package_name[:-7]
            
            prediction = analyze_json_tool(file_path, "benign")
            if prediction == "error":
                results["errors"] += 1
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
        json_files = glob.glob(os.path.join(malware_folder, "*.json"))
        
        for file_path in json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            if package_name.endswith("-result"):
                package_name = package_name[:-7]
            
            if package_name in EXCLUDED_MALWARE_PACKAGES:
                continue
            
            prediction = analyze_json_tool(file_path, "malware")
            if prediction == "error":
                results["errors"] += 1
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

def evaluate_socketai_tool(base_path):
    """Evaluate socketai."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "errors": 0
    }
    
    benign_folder = os.path.join(base_path, "socketai", "benign")
    if os.path.exists(benign_folder):
        package_folders = [d for d in os.listdir(benign_folder) 
                          if os.path.isdir(os.path.join(benign_folder, d))]
        
        for package_name in package_folders:
            package_folder_path = os.path.join(benign_folder, package_name)
            
            prediction = analyze_socketai(package_folder_path, "benign")
            if prediction == "error":
                results["errors"] += 1
                continue
            
            results["benign_total"] += 1
            
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    malware_folder = os.path.join(base_path, "socketai", "malware")
    if os.path.exists(malware_folder):
        package_folders = [d for d in os.listdir(malware_folder) 
                          if os.path.isdir(os.path.join(malware_folder, d))]
        
        for package_name in package_folders:
            if package_name in EXCLUDED_MALWARE_PACKAGES:
                continue
            
            package_folder_path = os.path.join(malware_folder, package_name)
            
            prediction = analyze_socketai(package_folder_path, "malware")
            if prediction == "error":
                results["errors"] += 1
                continue
            
            results["malware_total"] += 1
            
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

def evaluate_csv_model(model_results, model_name):
    """Evaluate a model from CSV verdicts."""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "errors": 0
    }
    
    if model_name not in model_results:
        print(f"No results found for {model_name} model")
        return results
    
    model_data = model_results[model_name]
    
    if "benign" in model_data:
        benign_results = model_data["benign"]
        
        for package_name, prediction in benign_results.items():
            results["benign_total"] += 1
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    if "malware" in model_data:
        malware_results = model_data["malware"]
        
        for package_name, prediction in malware_results.items():
            results["malware_total"] += 1
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

def compare_malkg_with_gpt(all_results, base_path):
    """Compare MalKG errors with the GPT models."""
    comparison_results = {
        "malkg_correct_benign_gpt_wrong": [],
        "malkg_correct_malware_gpt_wrong": []
    }
    
    if "malkg" not in all_results or "gpt-4.1-mini" not in all_results:
        return comparison_results
    
    malkg_results = all_results["malkg"]["detailed_results"]
    gpt_mini_results = all_results["gpt-4.1-mini"]["detailed_results"]
    
    for package_name in malkg_results:
        if package_name not in gpt_mini_results:
            continue
        
        malkg_data = malkg_results[package_name]
        gpt_mini_data = gpt_mini_results[package_name]
        
        actual_label = malkg_data["actual_label"]
        malkg_pred = malkg_data["prediction"]
        gpt_mini_pred = gpt_mini_data["prediction"]
        
        if actual_label == "benign" and malkg_pred == "benign" and gpt_mini_pred == "malware":
            if actual_label == "benign":
                source_path = f"{PROJECT_ROOT}/Dataset/NPM/evaluation/unzip_benign/{package_name}"
            
            comparison_results["malkg_correct_benign_gpt_wrong"].append({
                "package_name": package_name,
                "malkg_json": malkg_data["json_path"],
                "gpt_mini_json": gpt_mini_data["json_path"],
                "source_path": source_path
            })
        
        elif actual_label == "malware" and malkg_pred == "malware" and gpt_mini_pred == "benign":
            source_path = f"{PROJECT_ROOT}/Dataset/NPM/evaluation/unzip_malware/{package_name}"
            
            comparison_results["malkg_correct_malware_gpt_wrong"].append({
                "package_name": package_name,
                "malkg_json": malkg_data["json_path"],
                "gpt_mini_json": gpt_mini_data["json_path"],
                "source_path": source_path
            })
    
    return comparison_results

def save_results_to_file(all_results, output_file, comparison_results=None):
    """Write the results table."""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("NPM Package Malware Detection Tools Evaluation Report\n")
        f.write("=" * 100 + "\n\n")
        
        f.write("## Tool Evaluation Summary\n\n")
        f.write("| Tool Name | Total | Benign | Malware | Accuracy | Precision | Recall | F1 Score | TP | TN | FP | FN | FP Rate | FN Rate |\n")
        f.write("|" + "-" * 12 + "|" + "-" * 10 + "|" + "-" * 10 + "|" + "-" * 10 + "|" + "-" * 8 + "|" + "-" * 8 + "|" + "-" * 8 + "|" + "-" * 8 + "|" + "-" * 6 + "|" + "-" * 6 + "|" + "-" * 6 + "|" + "-" * 6 + "|" + "-" * 8 + "|" + "-" * 8 + "|\n")
        
        for tool_name, tool_results in sorted(all_results.items()):
            total_samples = tool_results["benign_total"] + tool_results["malware_total"]
            false_positive_rate = tool_results["false_positive"] / tool_results["benign_total"] if tool_results["benign_total"] > 0 else 0
            false_negative_rate = tool_results["false_negative"] / tool_results["malware_total"] if tool_results["malware_total"] > 0 else 0
            
            f.write(
                f"| {tool_name:<12} "
                f"| {total_samples:<8} "
                f"| {tool_results['benign_total']:<8} "
                f"| {tool_results['malware_total']:<8} "
                f"| {tool_results['accuracy']*100:>6.2f}% "
                f"| {tool_results['precision']*100:>6.2f}% "
                f"| {tool_results['recall']*100:>6.2f}% "
                f"| {tool_results['f1']*100:>6.2f}% "
                f"| {tool_results['true_positive']:>4} "
                f"| {tool_results['true_negative']:>4} "
                f"| {tool_results['false_positive']:>4} "
                f"| {tool_results['false_negative']:>4} "
                f"| {false_positive_rate*100:>6.2f}% "
                f"| {false_negative_rate*100:>6.2f}% |\n"
            )
        
        f.write("\n\n")
        f.write("=" * 100 + "\n")
        f.write("## Detailed Evaluation Results\n")
        f.write("=" * 100 + "\n\n")
        
        for tool_name, tool_results in sorted(all_results.items()):
            f.write(f"\n### {tool_name}\n")
            f.write("-" * 80 + "\n\n")
            
            f.write("**Basic Statistics:**\n")
            f.write(f"- Total benign samples: {tool_results['benign_total']}\n")
            f.write(f"- Total malware samples: {tool_results['malware_total']}\n")
            f.write(f"- Total samples: {tool_results['benign_total'] + tool_results['malware_total']}\n")
            if tool_results.get('errors', 0) > 0:
                f.write(f"- Processing errors: {tool_results['errors']}\n")
            f.write("\n")
            
            f.write("**Confusion Matrix:**\n")
            f.write(f"- True Positives (TP - correctly identified malware): {tool_results['true_positive']}\n")
            f.write(f"- True Negatives (TN - correctly identified benign): {tool_results['true_negative']}\n")
            f.write(f"- False Positives (FP - benign misclassified as malware): {tool_results['false_positive']}\n")
            f.write(f"- False Negatives (FN - malware misclassified as benign): {tool_results['false_negative']}\n")
            f.write("\n")
            
            f.write("**Evaluation Metrics:**\n")
            f.write(f"- Accuracy: {tool_results['accuracy']*100:.2f}%\n")
            f.write(f"- Precision: {tool_results['precision']*100:.2f}%\n")
            f.write(f"- Recall: {tool_results['recall']*100:.2f}%\n")
            f.write(f"- F1 score: {tool_results['f1']*100:.2f}%\n")
            
            false_positive_rate = tool_results['false_positive'] / tool_results['benign_total'] if tool_results['benign_total'] > 0 else 0
            false_negative_rate = tool_results['false_negative'] / tool_results['malware_total'] if tool_results['malware_total'] > 0 else 0
            f.write(f"- False Positive Rate: {false_positive_rate*100:.2f}%\n")
            f.write(f"- False Negative Rate: {false_negative_rate*100:.2f}%\n")
            f.write("\n")
            
            if tool_results["misclassified_benign"]:
                f.write(f"**False Positive Samples List ({len(tool_results['misclassified_benign'])} packages):**\n")
                for i, package in enumerate(tool_results["misclassified_benign"][:20], 1):
                    f.write(f"{i}. {package}\n")
                if len(tool_results["misclassified_benign"]) > 20:
                    f.write(f"... and {len(tool_results['misclassified_benign']) - 20} other packages\n")
                f.write("\n")
            
            if tool_results["misclassified_malware"]:
                f.write(f"**False Negative Samples List ({len(tool_results['misclassified_malware'])} packages):**\n")
                for i, package in enumerate(tool_results["misclassified_malware"][:20], 1):
                    f.write(f"{i}. {package}\n")
                if len(tool_results["misclassified_malware"]) > 20:
                    f.write(f"... and {len(tool_results['misclassified_malware']) - 20} other packages\n")
                f.write("\n")
                
                if tool_name == "malkg":
                    f.write(f"**malkg false negative file paths:**\n")
                    for package in tool_results["misclassified_malware"]:
                        source_path = f"{PROJECT_ROOT}/Dataset/NPM/evaluation/unzip_malware/{package}"
                        f.write(f"{source_path}\n")
                    f.write("\n")
            
            f.write("\n")
        
        if comparison_results:
            f.write("\n")
            f.write("=" * 100 + "\n")
            f.write("## MalKG vs GPT Models Comparison\n")
            f.write("=" * 100 + "\n\n")
            
            f.write(f"### Case 1: MalKG correctly identified as benign, but GPT-4.1-mini incorrectly identified as malware\n")
            f.write(f"Total count: {len(comparison_results['malkg_correct_benign_gpt_wrong'])}\n\n")
            
            if comparison_results["malkg_correct_benign_gpt_wrong"]:
                for i, item in enumerate(comparison_results["malkg_correct_benign_gpt_wrong"], 1):
                    f.write(f"{i}. Package: {item['package_name']}\n")
                    f.write(f"   - MalKG JSON: {item['malkg_json']}\n")
                    f.write(f"   - GPT-4.1-mini JSON: {item['gpt_mini_json']}\n")
                    f.write(f"   - Source Path: {item['source_path']}\n")
                    f.write("\n")
            else:
                f.write("No such cases found.\n\n")
            
            f.write(f"### Case 2: MalKG correctly identified as malware, but GPT-4.1-mini incorrectly identified as benign\n")
            f.write(f"Total count: {len(comparison_results['malkg_correct_malware_gpt_wrong'])}\n\n")
            
            if comparison_results["malkg_correct_malware_gpt_wrong"]:
                for i, item in enumerate(comparison_results["malkg_correct_malware_gpt_wrong"], 1):
                    f.write(f"{i}. Package: {item['package_name']}\n")
                    f.write(f"   - MalKG JSON: {item['malkg_json']}\n")
                    f.write(f"   - GPT-4.1-mini JSON: {item['gpt_mini_json']}\n")
                    f.write(f"   - Source Path: {item['source_path']}\n")
                    f.write("\n")
            else:
                f.write("No such cases found.\n\n")

def main():
    """Entry point."""
    base_path = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results/evaluation"
    
    print("=" * 80)
    print("Starting evaluation of NPM package malware detection tools")
    print("=" * 80)
    
    all_results = {}
    
    folder_tools = {
        "guarddog": analyze_guarddog,
        "ossgadget": analyze_ossgadget,
        "packj_static": analyze_packj,
        "packj_trace": analyze_packj,
        "genie": analyze_genie
    }
    
    print("\nEvaluating folder-based tools...")
    for tool_name, tool_function in folder_tools.items():
        print(f"\nEvaluating tool: {tool_name}")
        tool_results = evaluate_folder_based_tool(base_path, tool_name, tool_function)
        all_results[tool_name] = tool_results
        
        print(f"  Total samples: {tool_results['benign_total'] + tool_results['malware_total']}")
        print(f"  Accuracy: {tool_results['accuracy']*100:.2f}%")
        print(f"  Precision: {tool_results['precision']*100:.2f}%")
        print(f"  Recall: {tool_results['recall']*100:.2f}%")
        print(f"  F1 score: {tool_results['f1']*100:.2f}%")
        print(f"  False positives: {tool_results['false_positive']}, False negatives: {tool_results['false_negative']}")
        if tool_results.get('errors', 0) > 0:
            print(f"  Errors: {tool_results['errors']}")
    
    json_tools = ["gpt-4.1-mini", "malkg"]
    
    print("\nEvaluating JSON-based tools...")
    for tool_name in json_tools:
        print(f"\nEvaluating tool: {tool_name}")
        tool_results = evaluate_json_tool(base_path, tool_name)
        all_results[tool_name] = tool_results
        
        print(f"  Total samples: {tool_results['benign_total'] + tool_results['malware_total']}")
        print(f"  Accuracy: {tool_results['accuracy']*100:.2f}%")
        print(f"  Precision: {tool_results['precision']*100:.2f}%")
        print(f"  Recall: {tool_results['recall']*100:.2f}%")
        print(f"  F1 score: {tool_results['f1']*100:.2f}%")
        print(f"  False positives: {tool_results['false_positive']}, False negatives: {tool_results['false_negative']}")
        if tool_results.get('errors', 0) > 0:
            print(f"  Errors: {tool_results['errors']}")
    
    print("\nEvaluating tool: socketai")
    socketai_results = evaluate_socketai_tool(base_path)
    all_results["socketai"] = socketai_results
    
    print(f"  Total samples: {socketai_results['benign_total'] + socketai_results['malware_total']}")
    print(f"  Accuracy: {socketai_results['accuracy']*100:.2f}%")
    print(f"  Precision: {socketai_results['precision']*100:.2f}%")
    print(f"  Recall: {socketai_results['recall']*100:.2f}%")
    print(f"  F1 score: {socketai_results['f1']*100:.2f}%")
    print(f"  False positives: {socketai_results['false_positive']}, False negatives: {socketai_results['false_negative']}")
    if socketai_results.get('errors', 0) > 0:
        print(f"  Errors: {socketai_results['errors']}")
    
    print("\nLoading SAP model results...")
    sap_csv_path = os.path.join(base_path, "sap", "sap_detection_results.csv")
    if os.path.exists(sap_csv_path):
        sap_results = analyze_sap_models(sap_csv_path)
        
        if sap_results:
            for model_name in ["dt", "rf", "xgb"]:
                tool_name = f"sap-{model_name}"
                print(f"\nEvaluating tool: {tool_name}")
                model_results = evaluate_csv_model(sap_results, model_name)
                all_results[tool_name] = model_results
                
                print(f"  Total samples: {model_results['benign_total'] + model_results['malware_total']}")
                print(f"  Accuracy: {model_results['accuracy']*100:.2f}%")
                print(f"  Precision: {model_results['precision']*100:.2f}%")
                print(f"  Recall: {model_results['recall']*100:.2f}%")
                print(f"  F1 score: {model_results['f1']*100:.2f}%")
                print(f"  False positives: {model_results['false_positive']}, False negatives: {model_results['false_negative']}")
    else:
        print(f"  Warning: SAP result file does not exist: {sap_csv_path}")
    
    print("\nLoading MalPacDetector model results...")
    malpac_csv_path = os.path.join(base_path, "MalPacDetector", "filtered_detection_results.csv")
    if os.path.exists(malpac_csv_path):
        malpac_results = analyze_malpacdetector_models(malpac_csv_path)
        
        if malpac_results:
            for model_name in ["mlp", "nb", "svm"]:
                tool_name = f"malpac-{model_name}"
                print(f"\nEvaluating tool: {tool_name}")
                model_results = evaluate_csv_model(malpac_results, model_name)
                all_results[tool_name] = model_results
                
                print(f"  Total samples: {model_results['benign_total'] + model_results['malware_total']}")
                print(f"  Accuracy: {model_results['accuracy']*100:.2f}%")
                print(f"  Precision: {model_results['precision']*100:.2f}%")
                print(f"  Recall: {model_results['recall']*100:.2f}%")
                print(f"  F1 score: {model_results['f1']*100:.2f}%")
                print(f"  False positives: {model_results['false_positive']}, False negatives: {model_results['false_negative']}")
    else:
        print(f"  Warning: MalPacDetector result file does not exist: {malpac_csv_path}")
    
    print("\nComparing MalKG with GPT models...")
    comparison_results = compare_malkg_with_gpt(all_results, base_path)
    print(f"  MalKG correct (benign) but GPT wrong: {len(comparison_results['malkg_correct_benign_gpt_wrong'])} cases")
    print(f"  MalKG correct (malware) but GPT wrong: {len(comparison_results['malkg_correct_malware_gpt_wrong'])} cases")
    
    output_file = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/npm_tool_evaluation_results.txt"
    save_results_to_file(all_results, output_file, comparison_results)
    print(f"\n\n{'='*80}")
    print(f"Evaluation complete! Detailed results saved to: {output_file}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
