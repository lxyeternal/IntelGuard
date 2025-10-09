import os
import json
import glob
import csv
from collections import defaultdict


def analyze_bandit4mal(package_folder_path, folder_type):
    """
    Analyze bandit4mal detection results
    bandit4mal的结果保存在包名文件夹中，每个包一个文件夹    
    在文件夹下有一个result.txt文件
    如果txt中存在"No issues identified."字符串或者整个txt是"benign"，就证明检测为良性的，否则为恶意的
    """
    try:
        result_file = os.path.join(package_folder_path, "result.txt")
        if not os.path.exists(result_file):
            # If result.txt is not found, consider it benign
            return "benign"
        
        with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "No issues identified." in content or content.strip() == "benign":
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {result_file}: {e}")
        return "error"

def analyze_guarddog(package_folder_path, folder_type):
    """
    Analyze guarddog detection results
    guarddog的结果保存在包名文件夹中，每个包一个文件夹
    在文件夹下有一个result.txt文件
    If the txt contains "Found 0 potentially malicious indicators" string or the entire txt is "benign", it means it is benign
    """
    try:
        result_file = os.path.join(package_folder_path, "result.txt")
        if not os.path.exists(result_file):
            # If result.txt is not found, consider it benign
            return "benign"
        
        with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "Found 0 potentially malicious indicators" in content or content.strip() == "benign":
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {result_file}: {e}")
        return "error"

def analyze_ossgadget(package_folder_path, folder_type):
    """
    Analyze ossgadget detection results
    ossgadget的结果保存在包名文件夹中，每个包一个文件夹
    在文件夹下有一个result.txt文件
    If the txt contains "0 matches found." or the entire txt is "benign", it means it is benign
    """
    try:
        result_file = os.path.join(package_folder_path, "result.txt")
        if not os.path.exists(result_file):
            # If result.txt is not found, consider it benign
            return "benign"
        
        with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "0 matches found." in content or content.strip() == "benign":
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {result_file}: {e}")
        return "error"

def analyze_pypiwarehouse(package_folder_path, folder_type):
    """
    Analyze pypiwarehouse detection results
    pypiwarehouse的结果保存在包名文件夹中，每个包一个文件夹
    在文件夹下有一个result.txt文件
    If the txt content is "benign" or empty, it means it is benign
    """
    try:
        result_file = os.path.join(package_folder_path, "result.txt")
        if not os.path.exists(result_file):
            # If result.txt is not found, consider it benign
            return "benign"
        
        with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
            if content == "benign" or content == "":
                return "benign"
            else:
                return "malware"
    except Exception as e:
        print(f"Error reading {result_file}: {e}")
        return "error"

def analyze_gpt41(file_path, folder_type):
    """
    Analyze gpt-4.1 and gpt-4.1-mini detection results
    结果保存为包名.txt文件（实际是JSON格式）
    If the JSON file contains "is_malicious" field and its value is true, it means it is malicious, otherwise it is benign
    """
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
    """
    Analyze socketai detection results
    socketai的结果保存在文件夹中，每个包一个文件夹，文件夹名就是包的hash
    在包文件夹下，有一个{hash}.txt文件（JSON格式）
    如果{hash}.txt中的is_malicious为true，则整个包为恶意
    """
    try:
        package_name = os.path.basename(package_folder_path)
        
        # 查找{hash}.txt文件
        hash_file = os.path.join(package_folder_path, f"{package_name}.txt")
        
        if not os.path.exists(hash_file):
            print(f"Warning: No {package_name}.txt found in {package_folder_path}")
            return "error"
        
        try:
            with open(hash_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                is_malicious = data.get("is_malicious", False)
                return "malware" if is_malicious else "benign"
        except Exception as e:
            print(f"Error parsing JSON from {hash_file}: {e}")
            return "error"
            
    except Exception as e:
        print(f"Error reading socketai result from {package_folder_path}: {e}")
        return "error"

def analyze_sap_models(csv_file_path):
    """
    分析SAP模型的检测结果
    解析CSV文件并返回每个模型在每个数据集上的检测结果
    PyPI只有evaluation和obfuscation两个数据集
    
    CSV格式：Package Name,dataset,label,DT,RF,XGB
    其中label是真实标签（benign或malware），DT/RF/XGB是预测结果（0=良性，1=恶意）
    """
    sap_results = {
        "evaluation": {"dt": {}, "rf": {}, "xgb": {}},
        "obfuscation": {"dt": {}, "rf": {}, "xgb": {}}
    }

    try:
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                package_name = row['Package Name']
                dataset_type = row['dataset']  # obfuscation 或 evaluation
                label = row['label']  # 真实标签：benign 或 malware
                
                if dataset_type not in sap_results:
                    continue
                
                # 对于每个模型，将预测结果转换为标签
                for model in ['dt', 'rf', 'xgb']:
                    model_key = model.upper()
                    prediction = int(row[model_key]) if model_key in row else 0
                    
                    # 预测结果：0=良性，1=恶意
                    predicted_label = "malware" if prediction == 1 else "benign"
                    
                    # 按真实标签分类存储
                    if label not in sap_results[dataset_type][model]:
                        sap_results[dataset_type][model][label] = {}
                    
                    sap_results[dataset_type][model][label][package_name] = predicted_label
        
        return sap_results
    except Exception as e:
        print(f"Error reading SAP CSV file {csv_file_path}: {e}")
        return None

def analyze_mulguard(csv_file_path):
    """
    分析MulGuard的检测结果
    解析CSV文件并返回每个模型在每个数据集上的检测结果
    
    CSV格式：dataset,package_type,package_name,decision_tree_(dt),multi-layer_perceptron_(mlp),naive_bayes_(nb),random_forest_(rf),sgd_classifier_(svm),xgboost_(xgb)
    其中package_type是真实标签（benign或malware），后面的列是预测结果（0/-1=良性，1=恶意）
    """
    mulguard_results = {
        "evaluation": {
            "dt": {}, "mlp": {}, "nb": {}, "rf": {}, "svm": {}, "xgb": {}
        },
        "obfuscation": {
            "dt": {}, "mlp": {}, "nb": {}, "rf": {}, "svm": {}, "xgb": {}
        }
    }
    
    try:
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dataset_type = row['dataset']  # evaluation 或 obfuscation
                package_type = row['package_type']  # 真实标签：benign 或 malware
                package_name = row['package_name']
                
                if dataset_type not in mulguard_results:
                    continue
                
                # 模型名称映射
                model_columns = {
                    'dt': 'decision_tree_(dt)',
                    'mlp': 'multi-layer_perceptron_(mlp)',
                    'nb': 'naive_bayes_(nb)',
                    'rf': 'random_forest_(rf)',
                    'svm': 'sgd_classifier_(svm)',
                    'xgb': 'xgboost_(xgb)'
                }
                
                for model_key, column_name in model_columns.items():
                    if column_name in row:
                        prediction_value = int(row[column_name])
                        
                        # 预测结果：0/-1=良性，1=恶意
                        predicted_label = "malware" if prediction_value == 1 else "benign"
                        
                        # 按真实标签分类存储
                        if package_type not in mulguard_results[dataset_type][model_key]:
                            mulguard_results[dataset_type][model_key][package_type] = {}
                        
                        mulguard_results[dataset_type][model_key][package_type][package_name] = predicted_label
        
        return mulguard_results
    except Exception as e:
        print(f"Error reading MulGuard CSV file {csv_file_path}: {e}")
        return None

def analyze_malkg(json_file_path, folder_type):
    """
    分析MalKG的检测结果
    MalKG的结果保存为JSON文件，每个包一个JSON文件
    JSON中的is_malicious字段表示预测结果：True=恶意，False=良性
    """
    try:
        with open(json_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            
            # 检查是否成功执行
            if data.get('status') != 'success':
                return "error"
            
            # 获取预测结果
            is_malicious = data.get('is_malicious', False)
            
            if is_malicious:
                return "malware"
            else:
                return "benign"
    except Exception as e:
        print(f"Error reading {json_file_path}: {e}")
        return "error"

def calculate_metrics(true_positives, true_negatives, false_positives, false_negatives):
    """计算精确度、召回率、F1分数等评价指标"""
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

def evaluate_folder_based_tool(base_path, dataset_type, tool_name, tool_function):
    """评估基于文件夹结构的工具（bandit4mal, guarddog, ossgadget, pypiwarehouse）"""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": []
    }
    
    # 处理良性样本
    benign_folder = os.path.join(base_path, dataset_type, tool_name, "benign")
    if os.path.exists(benign_folder):
        benign_package_folders = [d for d in os.listdir(benign_folder) 
                                 if os.path.isdir(os.path.join(benign_folder, d))]
        
        for package_name in benign_package_folders:
            package_folder_path = os.path.join(benign_folder, package_name)
            prediction = tool_function(package_folder_path, "benign")
            
            if prediction == "error":
                continue
                
            results["benign_total"] += 1
            
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    # 处理恶意样本
    malware_folder = os.path.join(base_path, dataset_type, tool_name, "malware")
    if os.path.exists(malware_folder):
        malware_package_folders = [d for d in os.listdir(malware_folder) 
                                  if os.path.isdir(os.path.join(malware_folder, d))]
        
        for package_name in malware_package_folders:
            package_folder_path = os.path.join(malware_folder, package_name)
            prediction = tool_function(package_folder_path, "malware")
            
            if prediction == "error":
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

def evaluate_file_based_tool(base_path, dataset_type, tool_name, tool_function):
    """评估基于文件结构的工具（gpt-4.1, gpt-4.1-mini）"""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "detailed_results": {}  # Store detailed results for comparison
    }
    
    # 处理良性样本
    benign_folder = os.path.join(base_path, dataset_type, tool_name, "benign")
    if os.path.exists(benign_folder):
        benign_txt_files = glob.glob(os.path.join(benign_folder, "*.txt"))
        
        for file_path in benign_txt_files:
            package_name = os.path.basename(file_path).replace(".txt", "")
            prediction = tool_function(file_path, "benign")
            
            if prediction == "error":
                continue
                
            results["benign_total"] += 1
            
            # Store detailed results
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
    
    # 处理恶意样本
    malware_folder = os.path.join(base_path, dataset_type, tool_name, "malware")
    if os.path.exists(malware_folder):
        malware_txt_files = glob.glob(os.path.join(malware_folder, "*.txt"))
        
        for file_path in malware_txt_files:
            package_name = os.path.basename(file_path).replace(".txt", "")
            prediction = tool_function(file_path, "malware")
            
            if prediction == "error":
                continue
            
            results["malware_total"] += 1
            
            # Store detailed results
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

def evaluate_socketai_tool(base_path, dataset_type):
    """专门评估socketai工具的检测效果，因为其文件结构与其他工具不同"""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": []
    }
    
    benign_folder = os.path.join(base_path, dataset_type, "socketai", "benign")
    if os.path.exists(benign_folder):
        benign_package_folders = [d for d in os.listdir(benign_folder) 
                                 if os.path.isdir(os.path.join(benign_folder, d))]
        
        for package_name in benign_package_folders:
            package_folder_path = os.path.join(benign_folder, package_name)
            prediction = analyze_socketai(package_folder_path, "benign")
            
            if prediction == "error":
                continue
                
            results["benign_total"] += 1
            
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    malware_folder = os.path.join(base_path, dataset_type, "socketai", "malware")
    if os.path.exists(malware_folder):
        malware_package_folders = [d for d in os.listdir(malware_folder) 
                                  if os.path.isdir(os.path.join(malware_folder, d))]
        
        for package_name in malware_package_folders:
            package_folder_path = os.path.join(malware_folder, package_name)
            prediction = analyze_socketai(package_folder_path, "malware")
            
            if prediction == "error":
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

def evaluate_sap_model(sap_results, dataset_type, model_name):
    """评估SAP模型在特定数据集上的检测效果"""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": []
    }
    
    if dataset_type not in sap_results or model_name not in sap_results[dataset_type]:
        print(f"没有找到 {dataset_type} 数据集的 {model_name} 模型结果")
        return results
    
    model_results = sap_results[dataset_type][model_name]
    
    if "benign" in model_results:
        benign_results = model_results["benign"]
        
        for package_name, prediction in benign_results.items():
            results["benign_total"] += 1
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    if "malware" in model_results:
        malware_results = model_results["malware"]
        
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

def evaluate_mulguard_model(mulguard_results, dataset_type, model_name):
    """评估MulGuard模型在特定数据集上的检测效果"""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": []
    }
    
    if dataset_type not in mulguard_results or model_name not in mulguard_results[dataset_type]:
        print(f"没有找到 {dataset_type} 数据集的 {model_name} 模型结果")
        return results
    
    model_results = mulguard_results[dataset_type][model_name]
    
    if "benign" in model_results:
        benign_results = model_results["benign"]
        
        for package_name, prediction in benign_results.items():
            results["benign_total"] += 1
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    if "malware" in model_results:
        malware_results = model_results["malware"]
        
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

def evaluate_malkg_tool(base_path, dataset_type):
    """评估MalKG工具的检测效果，结果保存为JSON文件"""
    results = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
        "benign_total": 0,
        "malware_total": 0,
        "misclassified_benign": [],
        "misclassified_malware": [],
        "detailed_results": {}  # Store detailed results for comparison
    }
    
    # 处理良性样本
    benign_folder = os.path.join(base_path, dataset_type, "malkg", "benign")
    if os.path.exists(benign_folder):
        benign_json_files = glob.glob(os.path.join(benign_folder, "*.json"))
        
        for json_file in benign_json_files:
            package_name = os.path.basename(json_file).replace(".json", "")
            prediction = analyze_malkg(json_file, "benign")
            
            if prediction == "error":
                continue
                
            results["benign_total"] += 1
            
            # Store detailed results
            results["detailed_results"][package_name] = {
                "actual_label": "benign",
                "prediction": prediction,
                "json_path": json_file
            }
            
            if prediction == "benign":
                results["true_negative"] += 1
            elif prediction == "malware":
                results["false_positive"] += 1
                results["misclassified_benign"].append(package_name)
    
    # 处理恶意样本
    malware_folder = os.path.join(base_path, dataset_type, "malkg", "malware")
    if os.path.exists(malware_folder):
        malware_json_files = glob.glob(os.path.join(malware_folder, "*.json"))
        
        for json_file in malware_json_files:
            package_name = os.path.basename(json_file).replace(".json", "")
            prediction = analyze_malkg(json_file, "malware")
            
            if prediction == "error":
                continue
            
            results["malware_total"] += 1
            
            # Store detailed results
            results["detailed_results"][package_name] = {
                "actual_label": "malware",
                "prediction": prediction,
                "json_path": json_file
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

def compare_malkg_with_gpt(all_results, dataset_type, base_path):
    """Compare MalKG results with GPT models (both gpt-4.1 and gpt-4.1-mini must be wrong)"""
    comparison_results = {
        "malkg_correct_benign_gpt_wrong": [],  # MalKG correct (TN), both GPTs wrong (FP)
        "malkg_correct_malware_gpt_wrong": []  # MalKG correct (TP), both GPTs wrong (FN)
    }
    
    if "malkg" not in all_results or "gpt-4.1-mini" not in all_results or "gpt-4.1" not in all_results:
        return comparison_results
    
    malkg_results = all_results["malkg"]["detailed_results"]
    gpt_mini_results = all_results["gpt-4.1-mini"]["detailed_results"]
    gpt_41_results = all_results["gpt-4.1"]["detailed_results"]
    
    # Compare results
    for package_name in malkg_results:
        if package_name not in gpt_mini_results or package_name not in gpt_41_results:
            continue
        
        malkg_data = malkg_results[package_name]
        gpt_mini_data = gpt_mini_results[package_name]
        gpt_41_data = gpt_41_results[package_name]
        
        actual_label = malkg_data["actual_label"]
        malkg_pred = malkg_data["prediction"]
        gpt_mini_pred = gpt_mini_data["prediction"]
        gpt_41_pred = gpt_41_data["prediction"]
        
        # Case 1: MalKG correctly identifies benign, but both GPTs incorrectly identify as malware
        if actual_label == "benign" and malkg_pred == "benign" and gpt_mini_pred == "malware" and gpt_41_pred == "malware":
            # Determine source path based on dataset type
            if dataset_type == "evaluation":
                source_path = f"/home2/wenbo/Documents/IntelliGraph/Dataset/PyPI/evaluation/unzip_benign/{package_name}"
            else:  # obfuscation
                source_path = f"/home2/wenbo/Documents/IntelliGraph/Dataset/PyPI/obfuscation/unzip_benign/{package_name}"
            
            comparison_results["malkg_correct_benign_gpt_wrong"].append({
                "package_name": package_name,
                "malkg_json": malkg_data["json_path"],
                "gpt_mini_json": gpt_mini_data["json_path"],
                "gpt_41_json": gpt_41_data["json_path"],
                "source_path": source_path
            })
        
        # Case 2: MalKG correctly identifies malware, but both GPTs incorrectly identify as benign
        elif actual_label == "malware" and malkg_pred == "malware" and gpt_mini_pred == "benign" and gpt_41_pred == "benign":
            if dataset_type == "evaluation":
                source_path = f"/home2/wenbo/Documents/IntelliGraph/Dataset/PyPI/evaluation/unzip_malware/{package_name}"
            else:  # obfuscation
                source_path = f"/home2/wenbo/Documents/IntelliGraph/Dataset/PyPI/obfuscation/unzip_malware/{package_name}"
            
            comparison_results["malkg_correct_malware_gpt_wrong"].append({
                "package_name": package_name,
                "malkg_json": malkg_data["json_path"],
                "gpt_mini_json": gpt_mini_data["json_path"],
                "gpt_41_json": gpt_41_data["json_path"],
                "source_path": source_path
            })
    
    return comparison_results

def save_results_to_file(results, output_file, comparison_results=None):
    """将结果保存到文本文件"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"PyPI工具检测效果统计报告\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("| 数据集 | 工具名称 | 样本总数 | 准确率 | 精确度 | 召回率 | F1分数 | 误报数 | 漏报数 | 误报率 | 漏报率 |\n")
        f.write("| ------ | -------- | -------- | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ |\n")
        
        for dataset_type, tools_data in results.items():
            for tool_name, tool_results in tools_data.items():
                total_samples = tool_results["benign_total"] + tool_results["malware_total"]
                false_positive_rate = tool_results["false_positive"] / tool_results["benign_total"] if tool_results["benign_total"] > 0 else 0
                false_negative_rate = tool_results["false_negative"] / tool_results["malware_total"] if tool_results["malware_total"] > 0 else 0
                
                f.write(
                    f"| {dataset_type} | {tool_name} | {total_samples} | {tool_results['accuracy']*100:.2f}% | "
                    f"{tool_results['precision']*100:.2f}% | {tool_results['recall']*100:.2f}% | {tool_results['f1']*100:.2f}% | "
                    f"{tool_results['false_positive']} | {tool_results['false_negative']} | "
                    f"{false_positive_rate*100:.2f}% | {false_negative_rate*100:.2f}% |\n"
                )
        
        f.write("\n\n详细结果:\n")
        f.write("=" * 80 + "\n\n")
        
        for dataset_type, tools_data in results.items():
            f.write(f"\n数据集: {dataset_type}\n")
            f.write("-" * 80 + "\n\n")
            
            for tool_name, tool_results in tools_data.items():
                f.write(f"\n{tool_name}详细结果:\n")
                f.write("-" * 40 + "\n")
                f.write(f"良性样本总数: {tool_results['benign_total']}\n")
                f.write(f"恶意样本总数: {tool_results['malware_total']}\n")
                
                f.write(f"真阳性 (TP): {tool_results['true_positive']} (正确识别恶意样本)\n")
                f.write(f"真阴性 (TN): {tool_results['true_negative']} (正确识别良性样本)\n")
                f.write(f"假阳性 (FP): {tool_results['false_positive']} (误报：错误地将良性识别为恶意)\n")
                f.write(f"假阴性 (FN): {tool_results['false_negative']} (漏报：错误地将恶意识别为良性)\n")
                f.write(f"准确率 (Accuracy): {tool_results['accuracy']*100:.2f}%\n")
                f.write(f"精确度 (Precision): {tool_results['precision']*100:.2f}%\n")
                f.write(f"召回率 (Recall): {tool_results['recall']*100:.2f}%\n")
                f.write(f"F1分数: {tool_results['f1']*100:.2f}%\n")
                
                false_positive_rate = tool_results['false_positive'] / tool_results['benign_total'] if tool_results['benign_total'] > 0 else 0
                false_negative_rate = tool_results['false_negative'] / tool_results['malware_total'] if tool_results['malware_total'] > 0 else 0
                f.write(f"误报率: {false_positive_rate*100:.2f}%\n")
                f.write(f"漏报率: {false_negative_rate*100:.2f}%\n\n")
                
                if tool_results["misclassified_benign"]:
                    f.write("误报样本列表 (良性被误判为恶意):\n")
                    for package in tool_results["misclassified_benign"]:
                        f.write(f"- {package}\n")
                    f.write("\n")
                
                if tool_results["misclassified_malware"]:
                    f.write("漏报样本列表 (恶意被误判为良性):\n")
                    for package in tool_results["misclassified_malware"]:
                        f.write(f"- {package}\n")
                    f.write("\n")
        
        # Add comparison results section
        if comparison_results:
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("## MalKG vs GPT Models Comparison\n")
            f.write("=" * 80 + "\n\n")
            
            for dataset_type, dataset_comparison in comparison_results.items():
                f.write(f"\n### Dataset: {dataset_type}\n")
                f.write("-" * 80 + "\n\n")
                
                # Case 1: MalKG correct on benign, both GPTs wrong
                f.write(f"#### Case 1: MalKG correctly identified as benign, but GPT-4.1 and GPT-4.1-mini both incorrectly identified as malware\n")
                f.write(f"Total count: {len(dataset_comparison['malkg_correct_benign_gpt_wrong'])}\n\n")
                
                if dataset_comparison["malkg_correct_benign_gpt_wrong"]:
                    for i, item in enumerate(dataset_comparison["malkg_correct_benign_gpt_wrong"], 1):
                        f.write(f"{i}. Package: {item['package_name']}\n")
                        f.write(f"   - MalKG JSON: {item['malkg_json']}\n")
                        f.write(f"   - GPT-4.1-mini JSON: {item['gpt_mini_json']}\n")
                        f.write(f"   - GPT-4.1 JSON: {item['gpt_41_json']}\n")
                        f.write(f"   - Source Path: {item['source_path']}\n")
                        f.write("\n")
                else:
                    f.write("No such cases found.\n\n")
                
                # Case 2: MalKG correct on malware, both GPTs wrong
                f.write(f"#### Case 2: MalKG correctly identified as malware, but GPT-4.1 and GPT-4.1-mini both incorrectly identified as benign\n")
                f.write(f"Total count: {len(dataset_comparison['malkg_correct_malware_gpt_wrong'])}\n\n")
                
                if dataset_comparison["malkg_correct_malware_gpt_wrong"]:
                    for i, item in enumerate(dataset_comparison["malkg_correct_malware_gpt_wrong"], 1):
                        f.write(f"{i}. Package: {item['package_name']}\n")
                        f.write(f"   - MalKG JSON: {item['malkg_json']}\n")
                        f.write(f"   - GPT-4.1-mini JSON: {item['gpt_mini_json']}\n")
                        f.write(f"   - GPT-4.1 JSON: {item['gpt_41_json']}\n")
                        f.write(f"   - Source Path: {item['source_path']}\n")
                        f.write("\n")
                else:
                    f.write("No such cases found.\n\n")

def main():
    """主函数"""
    base_path = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results"
    sap_csv_paths = {
        "evaluation": "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/evaluation/sap/evaluation_detection_results.csv",
        "obfuscation": "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/pypi/results/obfuscation/sap/obfuscation_detection_results.csv"
    }
    dataset_types = ["evaluation", "obfuscation"]
    
    # 统计各数据集样本数量
    print("\n统计各数据集样本数量：")
    
    # 定义各种工具类型
    folder_based_tools = ["bandit4mal", "guarddog", "ossgadget", "pypiwarehouse"]
    file_based_tools = ["gpt-4.1", "gpt-4.1-mini"]
    
    for dataset_type in dataset_types:
        print(f"\n数据集: {dataset_type}")
        
        # 统计文件夹结构的工具
        for tool_name in folder_based_tools:
            benign_folder = os.path.join(base_path, dataset_type, tool_name, "benign")
            malware_folder = os.path.join(base_path, dataset_type, tool_name, "malware")
            
            benign_count = 0
            if os.path.exists(benign_folder):
                benign_count = len([d for d in os.listdir(benign_folder) 
                                  if os.path.isdir(os.path.join(benign_folder, d))])
            
            malware_count = 0
            if os.path.exists(malware_folder):
                malware_count = len([d for d in os.listdir(malware_folder) 
                                   if os.path.isdir(os.path.join(malware_folder, d))])
            
            print(f"  工具 {tool_name}:")
            print(f"    - 良性样本: {benign_count} 个包")
            print(f"    - 恶意样本: {malware_count} 个包")
            print(f"    - 总计: {benign_count + malware_count} 个包")
        
        # 统计文件结构的工具
        for tool_name in file_based_tools:
            benign_folder = os.path.join(base_path, dataset_type, tool_name, "benign")
            malware_folder = os.path.join(base_path, dataset_type, tool_name, "malware")
            
            benign_count = 0
            benign_py_files = 0
            if os.path.exists(benign_folder):
                benign_txt_files = glob.glob(os.path.join(benign_folder, "*.txt"))
                benign_count = len(benign_txt_files)
                
                for txt_file in benign_txt_files:
                    try:
                        with open(txt_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            benign_py_files += data.get("files_analyzed", 0)
                    except:
                        pass
            
            malware_count = 0
            malware_py_files = 0
            if os.path.exists(malware_folder):
                malware_txt_files = glob.glob(os.path.join(malware_folder, "*.txt"))
                malware_count = len(malware_txt_files)
                
                for txt_file in malware_txt_files:
                    try:
                        with open(txt_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            malware_py_files += data.get("files_analyzed", 0)
                    except:
                        pass
            
            print(f"  工具 {tool_name}:")
            print(f"    - 良性样本: {benign_count} 个包 ({benign_py_files} 个Python文件)")
            print(f"    - 恶意样本: {malware_count} 个包 ({malware_py_files} 个Python文件)")
            print(f"    - 总计: {benign_count + malware_count} 个包")
        
        # 统计socketai
        print(f"  工具 socketai:")
        benign_folder = os.path.join(base_path, dataset_type, "socketai", "benign")
        malware_folder = os.path.join(base_path, dataset_type, "socketai", "malware")
        
        benign_count = 0
        if os.path.exists(benign_folder):
            benign_count = len([d for d in os.listdir(benign_folder) 
                              if os.path.isdir(os.path.join(benign_folder, d))])
        
        malware_count = 0
        if os.path.exists(malware_folder):
            malware_count = len([d for d in os.listdir(malware_folder) 
                               if os.path.isdir(os.path.join(malware_folder, d))])
        
        print(f"    - 良性样本: {benign_count} 个包")
        print(f"    - 恶意样本: {malware_count} 个包")
        print(f"    - 总计: {benign_count + malware_count} 个包")
        
        # 统计MalKG
        print(f"  工具 malkg:")
        benign_folder = os.path.join(base_path, dataset_type, "malkg", "benign")
        malware_folder = os.path.join(base_path, dataset_type, "malkg", "malware")
        
        benign_count = 0
        if os.path.exists(benign_folder):
            benign_json_files = glob.glob(os.path.join(benign_folder, "*.json"))
            benign_count = len(benign_json_files)
        
        malware_count = 0
        if os.path.exists(malware_folder):
            malware_json_files = glob.glob(os.path.join(malware_folder, "*.json"))
            malware_count = len(malware_json_files)
        
        print(f"    - 良性样本: {benign_count} 个包")
        print(f"    - 恶意样本: {malware_count} 个包")
        print(f"    - 总计: {benign_count + malware_count} 个包")
    
    # 加载SAP结果
    print("\n正在加载SAP模型的检测结果...")
    all_sap_results = {}
    for dataset_type in dataset_types:
        print(f"  加载 {dataset_type} 数据集的SAP结果...")
        sap_results = analyze_sap_models(sap_csv_paths[dataset_type])
        if sap_results:
            all_sap_results[dataset_type] = sap_results[dataset_type]
    
    # 加载MulGuard结果
    print("\n正在加载MulGuard模型的检测结果...")
    all_mulguard_results = {}
    for dataset_type in dataset_types:
        print(f"  加载 {dataset_type} 数据集的MulGuard结果...")
        mulguard_csv_path = os.path.join(base_path, dataset_type, "MulGuard", "predictions.csv")
        if os.path.exists(mulguard_csv_path):
            mulguard_results = analyze_mulguard(mulguard_csv_path)
            if mulguard_results and dataset_type in mulguard_results:
                all_mulguard_results[dataset_type] = mulguard_results[dataset_type]
        else:
            print(f"    警告：找不到 {mulguard_csv_path}")
    
    # 开始评估
    print("\n开始评估各工具...")
    results = {}
    
    folder_tool_functions = {
        "bandit4mal": analyze_bandit4mal,
        "guarddog": analyze_guarddog,
        "ossgadget": analyze_ossgadget,
        "pypiwarehouse": analyze_pypiwarehouse
    }
    
    file_tool_functions = {
        "gpt-4.1": analyze_gpt41,
        "gpt-4.1-mini": analyze_gpt41
    }
    
    for dataset_type in dataset_types:
        print(f"\n正在评估数据集: {dataset_type}")
        results[dataset_type] = {}
        
        # 评估文件夹结构的工具
        for tool_name, tool_function in folder_tool_functions.items():
            print(f"  正在评估工具: {tool_name}")
            tool_results = evaluate_folder_based_tool(base_path, dataset_type, tool_name, tool_function)
            results[dataset_type][tool_name] = tool_results
            
            total_samples = tool_results["benign_total"] + tool_results["malware_total"]
            print(
                f"    样本总数: {total_samples}, 准确率: {tool_results['accuracy']*100:.2f}%, "
                f"精确度: {tool_results['precision']*100:.2f}%, 召回率: {tool_results['recall']*100:.2f}%, "
                f"F1: {tool_results['f1']*100:.2f}%, 误报: {tool_results['false_positive']}, "
                f"漏报: {tool_results['false_negative']}"
            )
        
        # 评估文件结构的工具
        for tool_name, tool_function in file_tool_functions.items():
            print(f"  正在评估工具: {tool_name}")
            tool_results = evaluate_file_based_tool(base_path, dataset_type, tool_name, tool_function)
            results[dataset_type][tool_name] = tool_results
            
            total_samples = tool_results["benign_total"] + tool_results["malware_total"]
            print(
                f"    样本总数: {total_samples}, 准确率: {tool_results['accuracy']*100:.2f}%, "
                f"精确度: {tool_results['precision']*100:.2f}%, 召回率: {tool_results['recall']*100:.2f}%, "
                f"F1: {tool_results['f1']*100:.2f}%, 误报: {tool_results['false_positive']}, "
                f"漏报: {tool_results['false_negative']}"
            )
        
        # 评估socketai
        print(f"  正在评估工具: socketai")
        socketai_results = evaluate_socketai_tool(base_path, dataset_type)
        results[dataset_type]["socketai"] = socketai_results
        
        total_samples = socketai_results["benign_total"] + socketai_results["malware_total"]
        print(
            f"    样本总数: {total_samples}, 准确率: {socketai_results['accuracy']*100:.2f}%, "
            f"精确度: {socketai_results['precision']*100:.2f}%, 召回率: {socketai_results['recall']*100:.2f}%, "
            f"F1: {socketai_results['f1']*100:.2f}%, 误报: {socketai_results['false_positive']}, "
            f"漏报: {socketai_results['false_negative']}"
        )
        
        # 评估MalKG
        print(f"  正在评估工具: malkg")
        malkg_results = evaluate_malkg_tool(base_path, dataset_type)
        results[dataset_type]["malkg"] = malkg_results
        
        total_samples = malkg_results["benign_total"] + malkg_results["malware_total"]
        print(
            f"    样本总数: {total_samples}, 准确率: {malkg_results['accuracy']*100:.2f}%, "
            f"精确度: {malkg_results['precision']*100:.2f}%, 召回率: {malkg_results['recall']*100:.2f}%, "
            f"F1: {malkg_results['f1']*100:.2f}%, 误报: {malkg_results['false_positive']}, "
            f"漏报: {malkg_results['false_negative']}"
        )
        
        # 评估SAP模型
        if dataset_type in all_sap_results:
            sap_models = ["dt", "rf", "xgb"]
            
            for model_name in sap_models:
                tool_name = f"sap-{model_name}"
                print(f"  正在评估工具: {tool_name}")
                
                # 需要构造一个包含当前数据集的sap_results字典
                sap_results_for_eval = {dataset_type: all_sap_results[dataset_type]}
                model_results = evaluate_sap_model(sap_results_for_eval, dataset_type, model_name)
                
                results[dataset_type][tool_name] = model_results
                
                total_samples = model_results["benign_total"] + model_results["malware_total"]
                print(
                    f"    样本总数: {total_samples}, 准确率: {model_results['accuracy']*100:.2f}%, "
                    f"精确度: {model_results['precision']*100:.2f}%, 召回率: {model_results['recall']*100:.2f}%, "
                    f"F1: {model_results['f1']*100:.2f}%, 误报: {model_results['false_positive']}, "
                    f"漏报: {model_results['false_negative']}"
                )
        
        # 评估MulGuard模型
        if dataset_type in all_mulguard_results:
            mulguard_models = ["dt", "mlp", "nb", "rf", "svm", "xgb"]
            
            for model_name in mulguard_models:
                tool_name = f"mulguard-{model_name}"
                print(f"  正在评估工具: {tool_name}")
                
                # 需要构造一个包含当前数据集的mulguard_results字典
                mulguard_results_for_eval = {dataset_type: all_mulguard_results[dataset_type]}
                model_results = evaluate_mulguard_model(mulguard_results_for_eval, dataset_type, model_name)
                
                results[dataset_type][tool_name] = model_results
                
                total_samples = model_results["benign_total"] + model_results["malware_total"]
                print(
                    f"    样本总数: {total_samples}, 准确率: {model_results['accuracy']*100:.2f}%, "
                    f"精确度: {model_results['precision']*100:.2f}%, 召回率: {model_results['recall']*100:.2f}%, "
                    f"F1: {model_results['f1']*100:.2f}%, 误报: {model_results['false_positive']}, "
                    f"漏报: {model_results['false_negative']}"
                )
    
    # Compare MalKG with GPT models for each dataset
    print("\nComparing MalKG with GPT models...")
    all_comparison_results = {}
    for dataset_type in dataset_types:
        if dataset_type in results:
            print(f"  Dataset: {dataset_type}")
            comparison_results = compare_malkg_with_gpt(results[dataset_type], dataset_type, base_path)
            all_comparison_results[dataset_type] = comparison_results
            print(f"    MalKG correct (benign) but both GPTs wrong: {len(comparison_results['malkg_correct_benign_gpt_wrong'])} cases")
            print(f"    MalKG correct (malware) but both GPTs wrong: {len(comparison_results['malkg_correct_malware_gpt_wrong'])} cases")
    
    # 保存结果
    output_file = "pypi_tool_evaluation_results.txt"
    save_results_to_file(results, output_file, all_comparison_results)
    print(f"\n详细结果已保存到文件: {output_file}")


if __name__ == "__main__":
    main() 