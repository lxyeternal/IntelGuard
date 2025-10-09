import os
import json
import glob

def analyze_json_tool(file_path):
    """Parse JSON-based tool results"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            if data.get("is_malicious", False):
                return "malware"
            else:
                return "benign"
    except Exception as e:
        return "error"

def main():
    base_path = "/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ2/npm/results/evaluation"
    
    # Load malkg results
    malkg_results = {"benign": {}, "malware": {}}
    
    benign_folder = os.path.join(base_path, "malkg", "benign")
    if os.path.exists(benign_folder):
        json_files = glob.glob(os.path.join(benign_folder, "*.json"))
        for file_path in json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            prediction = analyze_json_tool(file_path)
            if prediction != "error":
                malkg_results["benign"][package_name] = prediction
    
    malware_folder = os.path.join(base_path, "malkg", "malware")
    if os.path.exists(malware_folder):
        json_files = glob.glob(os.path.join(malware_folder, "*.json"))
        for file_path in json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            prediction = analyze_json_tool(file_path)
            if prediction != "error":
                malkg_results["malware"][package_name] = prediction
    
    # Load gpt-4.1-mini results
    gpt_mini_results = {"benign": {}, "malware": {}}
    
    benign_folder = os.path.join(base_path, "gpt-4.1-mini", "benign")
    if os.path.exists(benign_folder):
        json_files = glob.glob(os.path.join(benign_folder, "*.json"))
        for file_path in json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            prediction = analyze_json_tool(file_path)
            if prediction != "error":
                gpt_mini_results["benign"][package_name] = prediction
    
    malware_folder = os.path.join(base_path, "gpt-4.1-mini", "malware")
    if os.path.exists(malware_folder):
        json_files = glob.glob(os.path.join(malware_folder, "*.json"))
        for file_path in json_files:
            package_name = os.path.basename(file_path).replace(".json", "")
            prediction = analyze_json_tool(file_path)
            if prediction != "error":
                gpt_mini_results["malware"][package_name] = prediction
    
    print("=" * 80)
    print("Error Analysis: MalKG vs GPT-4.1-mini")
    print("=" * 80)
    
    # Find malkg false positives (benign predicted as malware)
    malkg_fp = [pkg for pkg, pred in malkg_results["benign"].items() if pred == "malware"]
    print(f"\nMalKG False Positives (benign -> malware): {len(malkg_fp)}")
    for pkg in malkg_fp:
        if pkg in gpt_mini_results["benign"]:
            gpt_pred = gpt_mini_results["benign"][pkg]
            print(f"  {pkg}: GPT-4.1-mini predicted as '{gpt_pred}'")
    
    # Find malkg false negatives (malware predicted as benign)
    malkg_fn = [pkg for pkg, pred in malkg_results["malware"].items() if pred == "benign"]
    print(f"\nMalKG False Negatives (malware -> benign): {len(malkg_fn)}")
    for pkg in malkg_fn:
        if pkg in gpt_mini_results["malware"]:
            gpt_pred = gpt_mini_results["malware"][pkg]
            print(f"  {pkg}: GPT-4.1-mini predicted as '{gpt_pred}'")
    
    # Find gpt-4.1-mini false positives
    gpt_fp = [pkg for pkg, pred in gpt_mini_results["benign"].items() if pred == "malware"]
    print(f"\nGPT-4.1-mini False Positives (benign -> malware): {len(gpt_fp)}")
    for pkg in gpt_fp:
        if pkg in malkg_results["benign"]:
            malkg_pred = malkg_results["benign"][pkg]
            print(f"  {pkg}: MalKG predicted as '{malkg_pred}'")
    
    # Find gpt-4.1-mini false negatives
    gpt_fn = [pkg for pkg, pred in gpt_mini_results["malware"].items() if pred == "benign"]
    print(f"\nGPT-4.1-mini False Negatives (malware -> benign): {len(gpt_fn)}")
    for pkg in gpt_fn:
        if pkg in malkg_results["malware"]:
            malkg_pred = malkg_results["malware"][pkg]
            print(f"  {pkg}: MalKG predicted as '{malkg_pred}'")
    
    # Analyze overlap
    print("\n" + "=" * 80)
    print("Overlap Analysis")
    print("=" * 80)
    
    # Case 1: MalKG correct on benign, GPT wrong
    case1_count = 0
    for pkg in gpt_fp:
        if pkg in malkg_results["benign"] and malkg_results["benign"][pkg] == "benign":
            case1_count += 1
            print(f"\nCase 1 found: {pkg}")
            print(f"  Actual: benign, MalKG: benign, GPT: malware")
    
    print(f"\nCase 1 total: {case1_count}")
    
    # Case 2: MalKG correct on malware, GPT wrong
    case2_count = 0
    for pkg in gpt_fn:
        if pkg in malkg_results["malware"] and malkg_results["malware"][pkg] == "malware":
            case2_count += 1
            print(f"\nCase 2 found: {pkg}")
            print(f"  Actual: malware, MalKG: malware, GPT: benign")
    
    print(f"\nCase 2 total: {case2_count}")
    
    # Check if packages exist in both tools
    print("\n" + "=" * 80)
    print("Dataset Coverage Check")
    print("=" * 80)
    
    malkg_benign_pkgs = set(malkg_results["benign"].keys())
    gpt_benign_pkgs = set(gpt_mini_results["benign"].keys())
    malkg_malware_pkgs = set(malkg_results["malware"].keys())
    gpt_malware_pkgs = set(gpt_mini_results["malware"].keys())
    
    print(f"\nBenign packages:")
    print(f"  MalKG: {len(malkg_benign_pkgs)}")
    print(f"  GPT-4.1-mini: {len(gpt_benign_pkgs)}")
    print(f"  Common: {len(malkg_benign_pkgs & gpt_benign_pkgs)}")
    print(f"  Only in MalKG: {len(malkg_benign_pkgs - gpt_benign_pkgs)}")
    print(f"  Only in GPT: {len(gpt_benign_pkgs - malkg_benign_pkgs)}")
    
    print(f"\nMalware packages:")
    print(f"  MalKG: {len(malkg_malware_pkgs)}")
    print(f"  GPT-4.1-mini: {len(gpt_malware_pkgs)}")
    print(f"  Common: {len(malkg_malware_pkgs & gpt_malware_pkgs)}")
    print(f"  Only in MalKG: {len(malkg_malware_pkgs - gpt_malware_pkgs)}")
    print(f"  Only in GPT: {len(gpt_malware_pkgs - malkg_malware_pkgs)}")

if __name__ == "__main__":
    main()



