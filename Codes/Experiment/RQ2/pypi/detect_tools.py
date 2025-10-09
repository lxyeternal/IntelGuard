import os
import sys
import subprocess
import multiprocessing
from pathlib import Path
import glob
import time
import signal

NUM_PROCESSES = 24
TOOL_TIMEOUT = 600

def run_with_timeout(cmd, timeout=TOOL_TIMEOUT):
    """Run command, if timeout is exceeded, terminate the process"""
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
    def __init__(self):
        self.base_dir = "/home2/wenbo/Documents/IntelliGraph"
        
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
        """确保所有输出目录存在"""
        for dataset_name in self.datasets:
            for tool in self.tools:
                for data_type in self.data_types:
                    output_dir = os.path.join(self.output_base, dataset_name, tool, data_type)
                    os.makedirs(output_dir, exist_ok=True)
                    
    def _get_output_path(self, dataset_name, tool, data_type, package_name):
        """获取输出文件路径"""
        output_dir = os.path.join(self.output_base, dataset_name, tool, data_type, package_name)
        os.makedirs(output_dir, exist_ok=True)
        return os.path.join(output_dir, "result.txt")
    
    def _find_zip_file(self, dataset_name, data_type, package_name):
        """根据数据集、类型和包名找到对应的压缩包路径"""
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
        """根据数据集、类型和包名找到对应的解压目录路径"""
        dataset_path = self.datasets[dataset_name]
        unzip_base = os.path.join(dataset_path, f"unzip_{data_type}")
        package_dir = os.path.join(unzip_base, package_name)
        
        if os.path.exists(package_dir) and os.path.isdir(package_dir):
            return package_dir
            
        return None
    
    def run_bandit(self, unzip_folder_path, output_file):
        """运行Bandit工具并保存结果"""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"跳过已处理的Bandit检测: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["bandit", "-r", unzip_folder_path]
        print(f"开始Bandit检测: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"Bandit检测超时: {os.path.basename(unzip_folder_path)}, 跳过")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Bandit检测完成: {os.path.basename(unzip_folder_path)}, 用时: {execution_time:.2f}秒")
            return output
    
    def run_guarddog(self, zip_file_path, output_file):
        """运行Guarddog工具并保存结果"""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"跳过已处理的Guarddog检测: {os.path.basename(zip_file_path)}")
            return None
            
        cmd = ["guarddog", "pypi", "scan", zip_file_path]
        print(f"开始Guarddog检测: {os.path.basename(zip_file_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"Guarddog检测超时: {os.path.basename(zip_file_path)}, 跳过")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Guarddog检测完成: {os.path.basename(zip_file_path)}, 用时: {execution_time:.2f}秒")
            return output
    
    def run_ossgadget(self, unzip_folder_path, output_file):
        """运行OSS Gadget工具并保存结果"""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"跳过已处理的OSSGadget检测: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["/home2/wenbo/Documents/PyPIAgent/Tools/OSSGadget/oss-detect-backdoor", unzip_folder_path]
        print(f"开始OSSGadget检测: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"OSSGadget检测超时: {os.path.basename(unzip_folder_path)}, 跳过")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"OSSGadget检测完成: {os.path.basename(unzip_folder_path)}, 用时: {execution_time:.2f}秒")
            return output
    
    def run_pypiwarehouse(self, unzip_folder_path, output_file):
        """运行PyPI Warehouse工具并保存结果"""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"跳过已处理的PyPIWarehouse检测: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["yara", "-r", "-s", "/home2/wenbo/Documents/PyPIAgent/Tools/PyPIWarehouse/setup_py_rules.yara", unzip_folder_path]
        print(f"开始PyPIWarehouse检测: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"PyPIWarehouse检测超时: {os.path.basename(unzip_folder_path)}, 跳过")
            return None
        else:
            output = stdout if stdout.strip() else "benign"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"PyPIWarehouse检测完成: {os.path.basename(unzip_folder_path)}, 用时: {execution_time:.2f}秒")
            return output
    
    def run_aura(self, unzip_folder_path, output_file):
        """运行Aura工具并保存结果"""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"跳过已处理的Aura检测: {os.path.basename(unzip_folder_path)}")
            return None
            
        cmd = ["aura", "scan", unzip_folder_path]
        print(f"开始Aura检测: {os.path.basename(unzip_folder_path)}")
        return_code, stdout, stderr, execution_time = run_with_timeout(cmd)
        
        if return_code == -1:
            print(f"Aura检测超时: {os.path.basename(unzip_folder_path)}, 跳过")
            return None
        else:
            if ("No code detections has been triggered" in stdout) or (stdout.strip() == ""):
                output = "benign"
            else:
                output = stdout if stdout.strip() else "benign"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Aura检测完成: {os.path.basename(unzip_folder_path)}, 用时: {execution_time:.2f}秒")
            return output
    
    def process_package(self, dataset_name, data_type, package_name):
        """处理单个包，调用所有检测工具并保存结果"""
        try:
            unzip_folder_path = self._find_unzip_dir(dataset_name, data_type, package_name)
            zip_file_path = self._find_zip_file(dataset_name, data_type, package_name)
            
            if not unzip_folder_path:
                print(f"警告: 找不到解压目录 {package_name}")
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
                print(f"跳过已完全处理的包: {dataset_name}/{data_type}/{package_name}")
                self.skipped_count += 1
                return
                
            print(f"正在处理 {dataset_name}/{data_type}/{package_name}...")
            
            if not os.path.exists(output_files["bandit4mal"]) or os.path.getsize(output_files["bandit4mal"]) == 0:
                if unzip_folder_path:
                    self.run_bandit(unzip_folder_path, output_files["bandit4mal"])
                else:
                    print(f"警告: 找不到解压目录 {package_name}，跳过Bandit检测")
            
            if (not os.path.exists(output_files["guarddog"]) or os.path.getsize(output_files["guarddog"]) == 0):
                if zip_file_path:
                    self.run_guarddog(zip_file_path, output_files["guarddog"])
                else:
                    print(f"警告: 找不到对应的压缩包 {package_name}，跳过Guarddog检测")
            
            if not os.path.exists(output_files["ossgadget"]) or os.path.getsize(output_files["ossgadget"]) == 0:
                if unzip_folder_path:
                    self.run_ossgadget(unzip_folder_path, output_files["ossgadget"])
                else:
                    print(f"警告: 找不到解压目录 {package_name}，跳过OSSGadget检测")
            
            if not os.path.exists(output_files["pypiwarehouse"]) or os.path.getsize(output_files["pypiwarehouse"]) == 0:
                if unzip_folder_path:
                    self.run_pypiwarehouse(unzip_folder_path, output_files["pypiwarehouse"])
                else:
                    print(f"警告: 找不到解压目录 {package_name}，跳过PyPIWarehouse检测")
            
            if not os.path.exists(output_files["aura"]) or os.path.getsize(output_files["aura"]) == 0:
                if unzip_folder_path:
                    self.run_aura(unzip_folder_path, output_files["aura"])
                else:
                    print(f"警告: 找不到解压目录 {package_name}，跳过Aura检测")
            
            print(f"完成处理 {dataset_name}/{data_type}/{package_name}")
            self.processed_count += 1
            
        except Exception as e:
            print(f"处理 {dataset_name}/{data_type}/{package_name} 时出错: {str(e)}")
    
    def collect_packages(self, dataset_name):
        """收集指定数据集中的所有包名"""
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
        """处理指定数据集中的所有包"""
        print(f"开始处理数据集: {dataset_name}")
        
        tasks = self.collect_packages(dataset_name)
        
        print(f"数据集 {dataset_name} 共找到 {len(tasks)} 个包")
        
        if num_processes > 1:
            with multiprocessing.Pool(processes=num_processes) as pool:
                pool.starmap(self.process_package, tasks)
        else:
            for task in tasks:
                self.process_package(*task)
        
        print(f"数据集 {dataset_name} 处理完成！")
        
    def process_all_datasets(self, num_processes=NUM_PROCESSES):
        """处理所有数据集"""
        total_processed = 0
        total_skipped = 0
        
        for dataset_name in self.datasets:
            self.processed_count = 0
            self.skipped_count = 0
            
            self.process_dataset(dataset_name, num_processes)
            
            total_processed += self.processed_count
            total_skipped += self.skipped_count
            
            print(f"数据集 {dataset_name} 处理结果: 新处理 {self.processed_count} 个，跳过已处理 {self.skipped_count} 个")
        
        print(f"所有数据集处理完成！总计: 新处理 {total_processed} 个，跳过已处理 {total_skipped} 个")

if __name__ == "__main__":
    try:
        print("清理可能的僵尸进程...")
        cleanup_cmd = """
        pkill -f bandit || true
        pkill -f guarddog || true
        pkill -f oss-detect-backdoor || true
        pkill -f yara || true
        pkill -f aura || true
        """
        subprocess.call(cleanup_cmd, shell=True)
        print("清理完成")
    except:
        print("清理进程时出错，继续执行...")
    
    print(f"使用 {NUM_PROCESSES} 个进程进行检测，工具超时时间: {TOOL_TIMEOUT}秒")
    
    detector = ToolDetector()
    detector.process_all_datasets() 