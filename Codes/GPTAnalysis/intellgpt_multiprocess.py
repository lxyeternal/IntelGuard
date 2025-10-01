# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : intellgpt_multiprocess.py
# @Project  : IntelliGraph
# Time      : 2025/10/01
# Author    : honywen
# version   : python 3.8
# Description: Multi-process version of IntelliLLM for parallel processing
"""

import os
import json
from multiprocessing import Process, Queue, cpu_count
from intellgpt import IntelliLLM


class IntelliLLMMultiProcess:
    def __init__(self, num_processes=None):
        """
        Initialize multi-process IntelliLLM
        
        Args:
            num_processes: Number of processes to use (default: CPU count)
        """
        self.num_processes = num_processes or cpu_count()
        print(f"Initialized with {self.num_processes} processes")
        
        # Initialize a single instance to get paths
        temp_instance = IntelliLLM()
        self.content_dir = temp_instance.content_dir
        self.json_dir = temp_instance.json_dir
        
    def collect_txt_files(self, source_dir):
        """
        Collect all txt files from a source directory
        
        Args:
            source_dir: Source directory name (e.g., 'bleepingcomputer')
            
        Returns:
            List of txt file names
        """
        content_source_dir = os.path.join(self.content_dir, source_dir)
        
        if not os.path.exists(content_source_dir):
            print(f"Source directory does not exist: {content_source_dir}")
            return []
        
        txt_files = []
        for file_name in os.listdir(content_source_dir):
            # Skip hidden files and non-txt files
            if not file_name.startswith('.') and file_name.endswith('.txt'):
                txt_files.append(file_name)
        
        return sorted(txt_files)  # Sort for consistent ordering
    
    def split_tasks(self, txt_files, num_processes):
        """
        Split txt files into chunks for each process
        
        Args:
            txt_files: List of txt file names
            num_processes: Number of processes
            
        Returns:
            List of file chunks, one for each process
        """
        if not txt_files:
            return []
        
        total_files = len(txt_files)
        chunk_size = (total_files + num_processes - 1) // num_processes  # Ceiling division
        
        chunks = []
        for i in range(num_processes):
            start_idx = i * chunk_size
            end_idx = min(start_idx + chunk_size, total_files)
            
            if start_idx < total_files:
                chunk = txt_files[start_idx:end_idx]
                chunks.append(chunk)
        
        return chunks
    
    @staticmethod
    def worker_process(process_id, source_dir, txt_files, result_queue):
        """
        Worker process function - each process runs this
        
        Args:
            process_id: Process identifier
            source_dir: Source directory name
            txt_files: List of txt files for this process to handle
            result_queue: Queue to report results
        """
        print(f"[Process {process_id}] Starting with {len(txt_files)} files")
        
        # Each process creates its own IntelliLLM instance
        ltmgpt = IntelliLLM()
        
        success_count = 0
        error_count = 0
        skipped_count = 0
        
        for idx, file_name in enumerate(txt_files, 1):
            try:
                # Check if already processed (verify.json exists)
                base_name = file_name.replace(".txt", "")
                verify_path = os.path.join(ltmgpt.json_dir, source_dir, base_name, "verify.json")
                
                if os.path.exists(verify_path):
                    skipped_count += 1
                    print(f"[Process {process_id}] ⊘ Skipped {idx}/{len(txt_files)}: {file_name} (already processed)")
                    continue
                
                print(f"[Process {process_id}] Processing {idx}/{len(txt_files)}: {file_name}")
                
                # Read text content
                txt_file_path = os.path.join(ltmgpt.content_dir, source_dir, file_name)
                txt_content = ltmgpt.read_txt(txt_file_path)
                
                # Process content using three-stage workflow
                ltmgpt.process_content(txt_content, source_dir, file_name)
                
                success_count += 1
                print(f"[Process {process_id}] ✓ Completed: {file_name}")
                
            except Exception as e:
                error_count += 1
                print(f"[Process {process_id}] ✗ Error processing {file_name}: {e}")
        
        # Report results
        result = {
            'process_id': process_id,
            'total': len(txt_files),
            'success': success_count,
            'error': error_count,
            'skipped': skipped_count,
            'files': txt_files
        }
        result_queue.put(result)
        
        print(f"[Process {process_id}] Finished: {success_count} success, {error_count} errors, {skipped_count} skipped")
    
    def process_source(self, source_dir):
        """
        Process all txt files in a source directory using multiple processes
        
        Args:
            source_dir: Source directory name (e.g., 'bleepingcomputer')
        """
        print(f"\n{'='*60}")
        print(f"Processing source: {source_dir}")
        print(f"{'='*60}")
        
        # Step 1: Collect all txt files
        txt_files = self.collect_txt_files(source_dir)
        
        if not txt_files:
            print(f"No txt files found in {source_dir}")
            return
        
        total_files = len(txt_files)
        print(f"Found {total_files} txt files")
        
        # Step 2: Split tasks among processes
        file_chunks = self.split_tasks(txt_files, self.num_processes)
        actual_processes = len(file_chunks)
        
        print(f"Splitting into {actual_processes} processes:")
        for i, chunk in enumerate(file_chunks):
            print(f"  Process {i}: {len(chunk)} files")
        
        # Step 3: Create and start processes
        processes = []
        result_queue = Queue()
        
        for i, chunk in enumerate(file_chunks):
            p = Process(
                target=self.worker_process,
                args=(i, source_dir, chunk, result_queue)
            )
            processes.append(p)
            p.start()
            print(f"Started Process {i}")
        
        # Step 4: Wait for all processes to complete
        print(f"\nWaiting for all processes to complete...")
        for p in processes:
            p.join()
        
        # Step 5: Collect and display results
        print(f"\n{'='*60}")
        print(f"Processing Summary for {source_dir}")
        print(f"{'='*60}")
        
        total_success = 0
        total_error = 0
        total_skipped = 0
        
        while not result_queue.empty():
            result = result_queue.get()
            print(f"Process {result['process_id']}: "
                  f"{result['success']} success, {result['error']} errors, "
                  f"{result['skipped']} skipped "
                  f"(out of {result['total']} files)")
            total_success += result['success']
            total_error += result['error']
            total_skipped += result['skipped']
        
        print(f"\nTotal: {total_success} success, {total_error} errors, {total_skipped} skipped "
              f"(out of {total_files} files)")
        print(f"{'='*60}\n")
    
    def start(self, source_dirs):
        """
        Start multi-process processing for multiple source directories
        
        Args:
            source_dirs: List of source directory names or single source directory
        """
        # Handle single source directory
        if isinstance(source_dirs, str):
            source_dirs = [source_dirs]
        
        print(f"\n{'#'*60}")
        print(f"Starting Multi-Process IntelliLLM Analysis")
        print(f"Number of processes: {self.num_processes}")
        print(f"Source directories: {', '.join(source_dirs)}")
        print(f"{'#'*60}\n")
        
        # Process each source directory
        for source_dir in source_dirs:
            self.process_source(source_dir)
        
        print(f"\n{'#'*60}")
        print(f"All Processing Complete!")
        print(f"{'#'*60}\n")


def main():
    """Main function with usage examples"""
    
    # Example 1: Use default number of processes (CPU count)
    mp_gpt = IntelliLLMMultiProcess()
    
    # Example 2: Specify number of processes
    # mp_gpt = IntelliLLMMultiProcess(num_processes=4)
    
    # Process single source
    # mp_gpt.start("bleepingcomputer")
    
    # Process multiple sources (sequential, each with multi-process)
    mp_gpt.start([
        "bleepingcomputer",
        "sonatype",
        "checkmarx",
        "medium",
        "qianxin",
        "datadoghq",
        "snyk"
    ])


if __name__ == '__main__':
    main()

