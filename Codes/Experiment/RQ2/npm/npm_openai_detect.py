"""Detect npm packages with an LLM over whole files."""
import os
import sys
import json
import glob
import time
import logging
import multiprocessing
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from functools import partial

sys.path.append(f"{PROJECT_ROOT}/Codes/GPTAnalysis")
from llmquery import LLMAgent

PROJECT_ROOT = Path(__file__).resolve().parents[4]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("NPMOpenAIDetect")

NUM_PROCESSES = 24
DETECTION_TIMEOUT = 300
MAX_FILES_PER_PACKAGE = 10

def load_prompt_template() -> str:
    """Read the detection prompt."""
    prompt_file = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/malware_detect_prompt.txt"
    try:
        with open(prompt_file, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"Prompt file not found: {prompt_file}")
        raise
    except Exception as e:
        logger.error(f"Error loading prompt file: {str(e)}")
        raise

def init_worker():
    """Create the LLM agent of a worker."""
    global llm_agent
    llm_agent = LLMAgent()

def prioritize_files(file_paths: List[str], base_path: str) -> List[str]:
    """Order files with index.js and package.json first."""
    priority_files = []
    other_files = []
    
    for file_path in file_paths:
        relative_path = os.path.relpath(file_path, base_path)
        filename = os.path.basename(file_path)
        
        if filename == "index.js":
            priority_files.insert(0, file_path)
        elif filename == "package.json":
            priority_files.insert(1 if priority_files else 0, file_path)
        else:
            other_files.append(file_path)
    
    all_files = priority_files + other_files
    return all_files[:MAX_FILES_PER_PACKAGE]

def process_package_worker(
    task: Tuple[str, str],
    unzip_benign_path: str,
    unzip_malware_path: str,
    output_paths: Dict[str, str],
    malware_detect_prompt: str
) -> None:
    """Worker: detect one package."""
    data_type, package_name = task
    
    try:
        if data_type == "benign":
            unzip_folder_path = os.path.join(unzip_benign_path, package_name)
            output_file = os.path.join(output_paths[data_type], f"{package_name}-result.json")
        else:
            unzip_folder_path = os.path.join(unzip_malware_path, package_name)
            output_file = os.path.join(output_paths[data_type], f"{package_name}-result.json")
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            logger.info(f"Skip processed package: {data_type}/{package_name}")
            return
        
        logger.info(f"Start processing {data_type}/{package_name}...")
        start_time = time.time()
        
        js_files = glob.glob(f"{unzip_folder_path}/**/*.js", recursive=True)
        json_files = glob.glob(f"{unzip_folder_path}/**/package.json", recursive=True)
        all_files = js_files + json_files
        
        if not all_files:
            logger.warning(f"No JavaScript/JSON files found in {package_name}")
            empty_result = {
                "package_name": package_name,
                "is_malicious": False,
                "files_analyzed": 0,
                "malicious_files": 0,
                "file_results": []
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(empty_result, f, ensure_ascii=False, indent=2)
                
            return
        
        selected_files = prioritize_files(all_files, unzip_folder_path)
        
        logger.info(f"Analyzing package {package_name} with GPT-4.1-mini ({len(selected_files)}/{len(all_files)} files)")
        file_results = []
        
        global llm_agent
        
        for file_path in selected_files:
            relative_path = os.path.relpath(file_path, unzip_folder_path)
            logger.info(f"GPT-4.1-mini analyzing file: {relative_path}")
            
            file_result = analyze_file(file_path, malware_detect_prompt, llm_agent)
            
            file_result["relative_path"] = relative_path
            file_results.append(file_result)
        
        malicious_files = sum(1 for fr in file_results if fr["is_malicious"])
        is_package_malicious = malicious_files > 0
        
        package_result = {
            "package_name": package_name,
            "is_malicious": is_package_malicious,
            "files_analyzed": len(file_results),
            "total_files": len(all_files),
            "malicious_files": malicious_files,
            "file_results": file_results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(package_result, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Complete analysis of {data_type}/{package_name} in {time.time() - start_time:.2f} seconds, is_malicious: {is_package_malicious}")
            
    except Exception as e:
        logger.error(f"Error processing package {data_type}/{package_name}: {str(e)}")
        error_result = {
            "package_name": package_name,
            "is_malicious": False,
            "error": str(e),
            "files_analyzed": 0,
            "malicious_files": 0,
            "file_results": []
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(error_result, f, ensure_ascii=False, indent=2)


def analyze_file(file_path: str, malware_detect_prompt: str, llm_agent: LLMAgent) -> Dict[str, Any]:
    """Ask the LLM about one file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code_content = f.read()
        
        if not code_content.strip():
            return {
                "file_path": file_path,
                "is_malicious": False,
                "malicious_behavior": ""
            }
        
        max_code_length = 50000
        if len(code_content) > max_code_length:
            code_content = code_content[:max_code_length] + "\n... [truncated]"
        
        prompt = malware_detect_prompt.replace("{CODE}", code_content)
        
        messages = [
            {"role": "system", "content": "You are a professional NPM package security analyst. Analyze the provided file (JavaScript code or package.json configuration) and determine if it contains malicious behavior."},
            {"role": "user", "content": prompt}
        ]
        
        response = llm_agent.perform_query(
            messages=messages,
            max_tokens=16000,
            temperature=0,
            top_p=0.3,
            frequency_penalty=0,
            presence_penalty=0,
            response_format={"type": "json_object"},
            seed=42
        )
        
        try:
            result = json.loads(response)
            is_malicious = result.get("is_malicious", False)
            
            return {
                "file_path": file_path,
                "is_malicious": is_malicious,
                "malicious_behavior": result.get("malicious_behavior", "")
            }
        except json.JSONDecodeError:
            logger.warning(f"GPT-4.1-mini returned not a valid JSON: {response[:100]}...")
            return {
                "file_path": file_path,
                "is_malicious": False,
                "malicious_behavior": "GPT-4.1-mini response parsing error"
            }
            
    except Exception as e:
        logger.error(f"Error using GPT-4.1-mini to analyze file {file_path}: {str(e)}")
        return {
            "file_path": file_path,
            "is_malicious": False,
            "malicious_behavior": f"Analysis error: {str(e)}"
        }


class NPMOpenAIDetector:
    """Run detection over the dataset."""
    def __init__(self):
        """Set the paths and the prompt."""
        self.base_path = f"{PROJECT_ROOT}/Dataset/NPM/evaluation"
        self.unzip_benign_path = os.path.join(self.base_path, "unzip_benign")
        self.unzip_malware_path = os.path.join(self.base_path, "unzip_malware")
        
        self.output_base = f"{PROJECT_ROOT}/Codes/Experiment/RQ2/npm/results/evaluation"
        self.output_paths = {
            "benign": os.path.join(self.output_base, "gpt-4.1-mini", "benign"),
            "malware": os.path.join(self.output_base, "gpt-4.1-mini", "malware")
        }
        
        self._ensure_output_dirs()
        
        self.malware_detect_prompt = load_prompt_template()
        
        self.llm_agent = LLMAgent()
        
        self.processed_count = 0
        self.skipped_count = 0
        
    def _ensure_output_dirs(self):
        """Create output directories."""
        for category in self.output_paths:
            os.makedirs(self.output_paths[category], exist_ok=True)
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Ask the LLM about one file."""
        return analyze_file(file_path, self.malware_detect_prompt, self.llm_agent)
    
    def process_package(self, data_type: str, package_name: str) -> None:
        """Detect one package."""
        process_package_worker(
            (data_type, package_name),
            self.unzip_benign_path,
            self.unzip_malware_path,
            self.output_paths,
            self.malware_detect_prompt
        )
        self.processed_count += 1
    
    def process_all_packages(self, num_processes=NUM_PROCESSES):
        """Detect all packages in parallel."""
        benign_packages = [f for f in os.listdir(self.unzip_benign_path) 
                          if os.path.isdir(os.path.join(self.unzip_benign_path, f))]
        
        malware_packages = [f for f in os.listdir(self.unzip_malware_path) 
                           if os.path.isdir(os.path.join(self.unzip_malware_path, f))]
        
        tasks = []
        for package in benign_packages:
            tasks.append(("benign", package))
        for package in malware_packages:
            tasks.append(("malware", package))
        
        logger.info(f"Found {len(benign_packages)} benign packages and {len(malware_packages)} malware packages")
        logger.info(f"Using GPT-4.1-mini model for analysis, {num_processes} processes enabled")
        logger.info(f"Max files per package: {MAX_FILES_PER_PACKAGE}")
        logger.info(f"Output directory: {os.path.dirname(self.output_paths['benign'])}")
        
        self.processed_count = 0
        self.skipped_count = 0
        
        for data_type, package_name in tasks:
            if data_type == "benign":
                output_file = os.path.join(self.output_paths[data_type], f"{package_name}-result.json")
            else:
                output_file = os.path.join(self.output_paths[data_type], f"{package_name}-result.json")
                
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                self.skipped_count += 1

        process_func = partial(
            process_package_worker,
            unzip_benign_path=self.unzip_benign_path,
            unzip_malware_path=self.unzip_malware_path,
            output_paths=self.output_paths,
            malware_detect_prompt=self.malware_detect_prompt
        )
        
        with multiprocessing.Pool(
            processes=num_processes,
            initializer=init_worker
        ) as pool:
            for i, _ in enumerate(pool.imap_unordered(process_func, tasks)):
                self.processed_count += 1
                if self.processed_count % 10 == 0 or self.processed_count == len(tasks) - self.skipped_count:
                    logger.info(f"Progress: {self.processed_count}/{len(tasks) - self.skipped_count} packages processed")
        
        logger.info(f"All packages processed! New processed: {self.processed_count} packages, skipped: {self.skipped_count} packages")

if __name__ == "__main__":
    logger.info(f"Start NPM malware code detection using OpenAI, multi-process version")
    
    detector = NPMOpenAIDetector()
    detector.process_all_packages(num_processes=NUM_PROCESSES)

