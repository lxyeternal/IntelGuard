"""
LLM-Based Code Slicer

This module provides functionality to extract semantically meaningful code slices
from Python source files using Large Language Models. Unlike rule-based approaches,
this slicer understands control flow and data dependencies to create complete,
contextually meaningful code fragments.

Key features:
- LLM-powered intelligent code slicing
- Preserves control and data dependencies  
- Extracts multiple independent code contexts per file
- Generates semantically complete code fragments
- Supports various LLM backends (OpenAI, local models, etc.)

Usage:
    python llm_code_slicer.py <package_path> [options]
"""

import os
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse
from datetime import datetime

project_root = str(Path(__file__).parent.parent.parent)
sys.path.insert(0, project_root)

from Codes.GPTAnalysis.llmquery import LLMAgent

class LLMCodeSlicer:
    """
    LLM-based code slicer that extracts semantically meaningful code fragments
    """
    
    def __init__(self, llm_agent: Optional[LLMAgent] = None):
        """
        Initialize the LLM code slicer
        
        Args:
            llm_agent: Optional LLM agent instance. If None, will create default agent.
        """
        self.llm_agent = llm_agent or LLMAgent()
        self.slicing_prompt = self._load_slicing_prompt()
        
    def _load_slicing_prompt(self) -> str:
        """Load the code slicing prompt template"""
        # Prompt文件在当前目录下
        prompt_path = Path(__file__).parent / "code_slicing_prompt.txt"
        
        if prompt_path.exists():
            return prompt_path.read_text(encoding='utf-8')
        else:
            raise FileNotFoundError(
                f"Slicing prompt file not found at {prompt_path}. "
                "Please ensure code_slicing_prompt.txt exists in Codes/Detect/"
            )
    

    def slice_code(self, code_content: str, file_path: str = None) -> Dict[str, Any]:
        """
        Slice Python code content using LLM
        
        Args:
            code_content: Python code content to slice
            file_path: Optional file path for metadata (used for slice IDs)
            
        Returns:
            Dictionary containing slicing results
        """
        try:
            if not code_content.strip():
                return {
                    "file_path": file_path,
                    "status": "empty",
                    "slices": [],
                    "error": None
                }
            
            prompt = self.slicing_prompt.format(code=code_content)
            
            messages = [{"role": "user", "content": prompt}]
            response = self.llm_agent.perform_query(messages)
            
            if isinstance(response, dict) and 'response' in response:
                response_content = response['response']
            else:
                response_content = str(response)
            
            slices_data = self._parse_llm_response(response_content)
            
            result = {
                "file_path": file_path,
                "status": "success",
                "slices": slices_data.get("slices", []),
                "analysis_summary": slices_data.get("analysis_summary", ""),
                "extraction_timestamp": datetime.now().isoformat(),
                "original_lines": len(code_content.splitlines()),
                "error": None
            }
            
            base_name = Path(file_path).stem if file_path else "code"
            for i, slice_data in enumerate(result["slices"]):
                slice_data["slice_id"] = f"{base_name}_slice_{i+1}"
                slice_data["file_path"] = file_path
                
            return result
            
        except Exception as e:
            return {
                "file_path": file_path,
                "status": "error", 
                "slices": [],
                "error": str(e),
                "extraction_timestamp": datetime.now().isoformat()
            }

    def slice_file(self, file_path: str) -> Dict[str, Any]:
        """
        Slice a single Python file using LLM
        
        Args:
            file_path: Path to the Python file to slice
            
        Returns:
            Dictionary containing slicing results
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            return self.slice_code(code_content, file_path)
            
        except Exception as e:
            return {
                "file_path": file_path,
                "status": "error", 
                "slices": [],
                "error": str(e),
                "extraction_timestamp": datetime.now().isoformat()
            }
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response to extract slicing results
        
        Args:
            response: Raw LLM response
            
        Returns:
            Parsed slicing data
        """
        try:
            import re
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
            
            if json_match:
                json_str = json_match.group(1)
                return json.loads(json_str)
            else:
                return json.loads(response)
                
        except json.JSONDecodeError:
            return {
                "slices": [{
                    "code": response
                }],
                "analysis_summary": "Failed to parse LLM response properly"
            }
    
    def slice_package(self, package_path: str) -> Dict[str, Any]:
        """
        Slice all Python files in a package
        
        Args:
            package_path: Path to the package directory
            
        Returns:
            Dictionary with 'files' key containing list of slicing results
        """
        package_path = Path(package_path)
        results = []
        
        python_files = []
        if package_path.is_file() and package_path.suffix == '.py':
            python_files = [package_path]
        else:
            python_files = list(package_path.rglob('*.py'))
        
        print(f"Found {len(python_files)} Python files to slice")
        
        for i, py_file in enumerate(python_files, 1):
            print(f"Processing file {i}/{len(python_files)}: {py_file.name}")
            
            result = self.slice_file(str(py_file))
            results.append(result)
            
            if result["status"] == "success":
                slice_count = len(result["slices"])
                print(f"  ✓ Extracted {slice_count} slices")
            else:
                print(f"  ✗ Failed: {result.get('error', 'Unknown error')}")
        
        return {"files": results}
    
    def save_slices(self, slices_data: List[Dict[str, Any]], output_path: str):
        """
        Save slicing results to JSON file
        
        Args:
            slices_data: List of slicing results
            output_path: Path to save the results
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        total_files = len(slices_data)
        successful_files = sum(1 for r in slices_data if r["status"] == "success")
        total_slices = sum(len(r["slices"]) for r in slices_data)
        
        summary = {
            "extraction_summary": {
                "total_files_processed": total_files,
                "successful_files": successful_files,
                "failed_files": total_files - successful_files,
                "total_slices_extracted": total_slices,
                "extraction_timestamp": datetime.now().isoformat()
            },
            "files": slices_data
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"\nSlicing results saved to: {output_path}")
        print(f"Summary: {successful_files}/{total_files} files processed successfully")
        print(f"Total slices extracted: {total_slices}")

def create_slicing_prompt_file():
    """Create the default slicing prompt file"""
    prompt_dir = Path(project_root) / "LLMs" / "prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    
    prompt_file = prompt_dir / "code_slicing_prompt.txt"
    
    if not prompt_file.exists():
        slicer = LLMCodeSlicer()
        prompt_content = slicer._get_default_slicing_prompt()
        prompt_file.write_text(prompt_content, encoding='utf-8')
        print(f"Created default slicing prompt: {prompt_file}")

def main():
    """Main function for command line usage"""
    parser = argparse.ArgumentParser(description='LLM-based Python code slicer')
    parser.add_argument('package_path', help='Path to Python package or file to slice')
    parser.add_argument('-o', '--output', help='Output file path for slicing results')
    parser.add_argument('--create-prompt', action='store_true', 
                       help='Create default slicing prompt file')
    
    args = parser.parse_args()
    
    if args.create_prompt:
        create_slicing_prompt_file()
        return
    
    slicer = LLMCodeSlicer()
    
    package_path = Path(args.package_path)
    if args.output:
        output_path = args.output
    else:
        if package_path.is_file():
            output_path = f"Results/malware_detection/{package_path.stem}_llm_slices.json"
        else:
            output_path = f"Results/malware_detection/{package_path.name}_llm_slices.json"
    
    print(f"Starting LLM-based code slicing for: {package_path}")
    print(f"Output will be saved to: {output_path}")
    
    results = slicer.slice_package(str(package_path))
    
    slicer.save_slices(results, output_path)
    
    print("\nLLM-based code slicing completed!")

if __name__ == "__main__":
    main()