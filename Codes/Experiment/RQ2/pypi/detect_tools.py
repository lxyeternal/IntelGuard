"""Run the baseline tools over the PyPI datasets."""
import os
import sys
import subprocess
import multiprocessing
from pathlib import Path
import glob
import time
import signal

PROJECT_ROOT = Path(__file__).resolve().parents[4]

NUM_PROCESSES = 24
TOOL_TIMEOUT = 600

def run_with_timeout(cmd, timeout=TOOL_TIMEOUT):
    """Run a command with a timeout."""
    start_time = time.time()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return_code = process.returncode
        execution_time = time.time() - start_time
        return (return_code, stdout, stderr, execution_time)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except:
            pass
        return (-1, f"Command timed out after {timeout} seconds", "", timeout)

class ToolDetector:
    """Run every tool on every package."""
    def __init__(self):
        """Set the dataset and output paths."""
        self.base_dir = f"{PROJECT_ROOT}"
        
        self.datasets = {
            "obfuscation": os.path.join(self.base_dir, "Dataset/PYPI/obfuscation"),
            "evaluation": os.path.join(self.base_dir, "Dataset/PYPI/evaluation")
        }
        
        self.output_base = os.path.join(self.base_dir, "Codes/Experiment/RQ2/pypi/results")
        
        self.tools = ["bandit4mal", "guarddog", "ossgadget"]
        
        self.data_types = ["benign", "malware"]
        
        self._ensure_output_dirs()
        
        self.processed_count = 0
        self.skipped_count = 0
        
    def _ensure_output_dirs(self):
        """Create output directories."""
        for dataset_name in self.datasets:
            for tool in self.tools:
                for data_type in self.data_types:
                    output_dir = os.path.join(self.output_base, dataset_name, tool, data_type)
                    os.makedirs(output_dir, exist_ok=True)
                    
    def _get_output_path(self, dataset_name, tool, data_type, package_name):
        """Result file of a package."""
        output_dir = os.path.join(self.output_base, dataset_name, tool, data_type, package_name)
        os.makedirs(output_dir, exist_ok=True)
        return os.path.join(output_dir, "result.txt")
    
    def _find_zip_file(self, dataset_name, data_type, package_name):
        """Archive of a package."""
        dataset_path = self.datasets[dataset_name]
        zip_base = os.path.join(dataset_path, f"zip_{data_type}")
        package_dir = os.path.join(zip_base, package_name)
        
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            for item in os.listdir(package_dir):
                item_path = os.path.join(package_dir, item)
                if os.path.isfile(item_path) and any(item.endswith(ext) for ext in ['.zip', '.tar.gz', '.whl', '.tgz', '.tar']):
                    return item_path
            
        return None
    
    def _find_unzip_dir(self, dataset_name, data_type, package_name):
        """Unpacked directory of a package."""
        dataset_path = self.datasets[dataset_name]
        unzip_base = os.path.join(dataset_path, f"unzip_{data_type}")
        package_dir = os.path.join(unzip_base, package_name)
        
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            return package_dir
            
        return None
    
    def run_bandit(self, unzip_folder_path, output_file):
        """Run bandit4mal."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"Bandit result exists, skipping: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["bandit", "-r", unzip_folder_path]
        print(f"Running Bandit: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"Bandit timed out: {os.path.basename(unzip_folder_path)}")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Bandit done: {os.path.basename(unzip_folder_path)} in {execution_time:.2f}s")
            return output
    
    def run_guarddog(self, zip_file_path, output_file):
        """Run guarddog."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"Guarddog result exists, skipping: {os.path.basename(zip_file_path)}")
            return None
            
        cmd = ["guarddog", "pypi", "scan", zip_file_path]
        print(f"Running Guarddog: {os.path.basename(zip_file_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"Guarddog timed out: {os.path.basename(zip_file_path)}")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Guarddog done: {os.path.basename(zip_file_path)} in {execution_time:.2f}s")
            return output
    
    def run_ossgadget(self, unzip_folder_path, output_file):
        """Run OSS Gadget."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"OSSGadget result exists, skipping: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = [os.environ.get("OSSGADGET_BIN", "oss-detect-backdoor"), unzip_folder_path]
        print(f"Running OSSGadget: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"OSSGadget timed out: {os.path.basename(unzip_folder_path)}")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"OSSGadget done: {os.path.basename(unzip_folder_path)} in {execution_time:.2f}s")
            return output
    
    def run_pypiwarehouse(self, unzip_folder_path, output_file):
        """Run the PyPI Warehouse rules."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"PyPIWarehouse result exists, skipping: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["yara", "-r", "-s", os.environ.get("PYPIWAREHOUSE_RULES", "setup_py_rules.yara"), unzip_folder_path]
        print(f"Running PyPIWarehouse: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"PyPIWarehouse timed out: {os.path.basename(unzip_folder_path)}")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"PyPIWarehouse done: {os.path.basename(unzip_folder_path)} in {execution_time:.2f}s")
            return output
    
    def run_aura(self, unzip_folder_path, output_file):
        """Run Aura."""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"Aura result exists, skipping: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["aura", "scan", unzip_folder_path]
        print(f"Running Aura: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"Aura timed out: {os.path.basename(unzip_folder_path)}")
            return None
        else:
            if ("No code detections has been triggered" in stdout) or (stdout.strip() == ""):
                output = "benign"
            else:
                output = stdout if stdout.strip() else "benign"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Aura done: {os.path.basename(unzip_folder_path)} in {execution_time:.2f}s")
            return output
    
    def process_package(self, dataset_name, data_type, package_name):
        """Run all tools on one package."""
        try:
            unzip_folder_path = self._find_unzip_dir(dataset_name, data_type, package_name)
            zip_file_path = self._find_zip_file(dataset_name, data_type, package_name)
            
            if not unzip_folder_path:
                print(f"Warning: no unpacked dir for {package_name}")
                return
                
            output_files = {
                "bandit4mal": self._get_output_path(dataset_name, "bandit4mal", data_type, package_name),
                "guarddog": self._get_output_path(dataset_name, "guarddog", data_type, package_name),
                "ossgadget": self._get_output_path(dataset_name, "ossgadget", data_type, package_name),
                "pypiwarehouse": self._get_output_path(dataset_name, "pypiwarehouse", data_type, package_name),
                "aura": self._get_output_path(dataset_name, "aura", data_type, package_name)
            }
            
            all_processed = True
            for tool, file_path in output_files.items():
                if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                    all_processed = False
                    break
                    
            if all_processed:
                print(f"All results exist, skipping: {dataset_name}/{data_type}/{package_name}")
                self.skipped_count += 1
                return
                
            print(f"Processing {dataset_name}/{data_type}/{package_name}...")
            
            if not os.path.exists(output_files["bandit4mal"]) or os.path.getsize(output_files["bandit4mal"]) == 0:
                if unzip_folder_path:
                    self.run_bandit(unzip_folder_path, output_files["bandit4mal"])
                else:
                    print(f"Warning: no unpacked dir for {package_name}, skipping Bandit")
            
            if (not os.path.exists(output_files["guarddog"]) or os.path.getsize(output_files["guarddog"]) == 0):
                if zip_file_path:
                    self.run_guarddog(zip_file_path, output_files["guarddog"])
                else:
                    print(f"Warning: no archive for {package_name}, skipping Guarddog")
            
            if not os.path.exists(output_files["ossgadget"]) or os.path.getsize(output_files["ossgadget"]) == 0:
                if unzip_folder_path:
                    self.run_ossgadget(unzip_folder_path, output_files["ossgadget"])
                else:
                    print(f"Warning: no unpacked dir for {package_name}, skipping OSSGadget")
            
            if not os.path.exists(output_files["pypiwarehouse"]) or os.path.getsize(output_files["pypiwarehouse"]) == 0:
                if unzip_folder_path:
                    self.run_pypiwarehouse(unzip_folder_path, output_files["pypiwarehouse"])
                else:
                    print(f"Warning: no unpacked dir for {package_name}, skipping PyPIWarehouse")
            
            if not os.path.exists(output_files["aura"]) or os.path.getsize(output_files["aura"]) == 0:
                if unzip_folder_path:
                    self.run_aura(unzip_folder_path, output_files["aura"])
                else:
                    print(f"Warning: no unpacked dir for {package_name}, skipping Aura")
            
            print(f"Finished {dataset_name}/{data_type}/{package_name}")
            self.processed_count += 1
            
        except Exception as e:
            print(f"Error processing {dataset_name}/{data_type}/{package_name}: {str(e)}")
    
    def collect_packages(self, dataset_name):
        """Package names of a dataset."""
        dataset_path = self.datasets[dataset_name]
        benign_path = os.path.join(dataset_path, "unzip_benign")
        malware_path = os.path.join(dataset_path, "unzip_malware")
        
        tasks = []
        
        if os.path.exists(benign_path):
            benign_packages = [f for f in os.listdir(benign_path) if os.path.isdir(os.path.join(benign_path, f))]
            for package_name in benign_packages:
                tasks.append((dataset_name, "benign", package_name))
        
        if os.path.exists(malware_path):
            malware_packages = [f for f in os.listdir(malware_path) if os.path.isdir(os.path.join(malware_path, f))]
            for package_name in malware_packages:
                tasks.append((dataset_name, "malware", package_name))
        
        return tasks
        
    def process_dataset(self, dataset_name, num_processes=NUM_PROCESSES):
        """Run all tools on one dataset."""
        print(f"Processing dataset: {dataset_name}")
        
        tasks = self.collect_packages(dataset_name)
        
        print(f"{dataset_name}: {len(tasks)} packages")
        
        if num_processes > 1:
            with multiprocessing.Pool(processes=num_processes) as pool:
                pool.starmap(self.process_package, tasks)
        else:
            for task in tasks:
                self.process_package(*task)
        
        print(f"{dataset_name} done")
        
    def process_all_datasets(self, num_processes=NUM_PROCESSES):
        """Run all tools on all datasets."""
        total_processed = 0
        total_skipped = 0
        
        for dataset_name in self.datasets:
            self.processed_count = 0
            self.skipped_count = 0
            
            self.process_dataset(dataset_name, num_processes)
            
            total_processed += self.processed_count
            total_skipped += self.skipped_count
            
            print(f"{dataset_name}: {self.processed_count} processed, {self.skipped_count} already done")
        
        print(f"All datasets done: {total_processed} processed, {total_skipped} already done")

if __name__ == "__main__":
    try:
        print("Cleaning up leftover processes...")
        cleanup_cmd = """
        pkill -f bandit || true
        pkill -f guarddog || true
        pkill -f oss-detect-backdoor || true
        pkill -f yara || true
        pkill -f aura || true
        """
        subprocess.call(cleanup_cmd, shell=True)
        print("Cleanup done")
    except:
        print("Cleanup failed, continuing...")
    
    print(f"Running with {NUM_PROCESSES} processes, tool timeout {TOOL_TIMEOUT}s")
    
    detector = ToolDetector()
    detector.process_all_datasets() 
