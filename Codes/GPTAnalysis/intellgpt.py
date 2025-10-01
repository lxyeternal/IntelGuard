# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : lst-gptuse.py
# @Project  : SCC_Intelligence
# Time      : 25/7/24 7:53 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""


import re
import os
import json
import base64
from llmquery import LLMAgent


class IntelliLLM:
    def __init__(self):
        self.source_dir = ""
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.json_dir = os.path.join(project_dir, "Dataset", "IntelliJson")
        self.content_dir = os.path.join(project_dir, "Dataset", "Content")
        self.images_dir = os.path.join(project_dir, "Dataset", "Image")
        # Three-stage prompt file paths
        self.intelli_related_prompt_path = os.path.join(current_dir, "Prompts", "intelli_related.txt")
        self.intelli_extract_prompt_path = os.path.join(current_dir, "Prompts", "intelli_extract_v2.txt")
        self.intelli_verify_prompt_path = os.path.join(current_dir, "Prompts", "intelli_verify_v2.txt")
           
        # Read prompt content
        self.intelli_related_prompt = self.read_file(self.intelli_related_prompt_path)
        self.intelli_extract_prompt = self.read_file(self.intelli_extract_prompt_path)
        self.intelli_verify_prompt = self.read_file(self.intelli_verify_prompt_path)
        
        # Initialize two different LLM agents for different stages
        # Small model for relevance analysis (Stage 1)
        self.small_model_agent = self._create_small_model_agent()
        # Large model for entity extraction and verification (Stage 2 & 3)
        self.large_model_agent = self._create_large_model_agent()
    
    def _create_small_model_agent(self):
        """Create LLM agent configured for small model (for relevance analysis)"""
        small_agent = LLMAgent()
        # Override config for small model efficiency
        small_agent.config.update({
            "openai_api_model": "gpt-4.1-mini",   # Use faster, cheaper mini model
        })
        # Reinitialize clients with new config
        small_agent._init_clients()
        print(f"Small model agent configured: {small_agent.config.get('openai_api_model', 'N/A')}")
        return small_agent
    
    def _create_large_model_agent(self):
        """Create LLM agent configured for large model (for extraction and verification)"""
        large_agent = LLMAgent()
        # Override config for large model power
        large_agent.config.update({
            "openai_api_model": "gpt-4.1",       # Use full GPT-4.1 model
            "default_max_tokens": 4000,          # Longer responses for detailed extraction
        })
        # Reinitialize clients with new config
        large_agent._init_clients()
        print(f"Large model agent configured: {large_agent.config.get('openai_api_model', 'N/A')}")
        return large_agent

    # Read prompt file content
    def read_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content


    def encode_image(self, image_path):
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')

    def extract_and_convert_image_paths(self, content):
        """Extract image paths from text and convert to local paths"""
        image_paths = []
        
        # Match lines starting with image:
        image_pattern = r'image:\s*(.+)'
        matches = re.findall(image_pattern, content)
        
        for match in matches:
            # Clean path, remove extra spaces
            original_path = match.strip()
            
            # Convert Windows path format to macOS format
            # D:/Desktop/malware/IntelliGraph\Dataset\Image\... -> /Users/blue/Documents/Github/IntelliGraph/Dataset/Image/...
            if original_path.startswith('D:/Desktop/malware/IntelliGraph'):
                # Replace root path
                converted_path = original_path.replace('D:/Desktop/malware/IntelliGraph', self.images_dir.replace('/Dataset/Image', ''))
                # Convert backslashes to forward slashes
                converted_path = converted_path.replace('\\', '/')
                
                # Check if file exists
                if os.path.exists(converted_path):
                    image_paths.append({
                        'original': original_path,
                        'converted': converted_path,
                        'exists': True
                    })
                else:
                    image_paths.append({
                        'original': original_path,
                        'converted': converted_path,
                        'exists': False
                    })
            else:
                # For other path formats, record but don't convert
                image_paths.append({
                    'original': original_path,
                    'converted': original_path,
                    'exists': os.path.exists(original_path) if original_path.startswith('/') else False
                })
        
        return image_paths


    @staticmethod
    def read_txt(file_name):
        with open(file_name, "r", encoding="utf-8") as f:
            content = f.read()
        return content

    def save_json(self, data, file_name):
        # Get folder path
        folder = os.path.dirname(file_name)
        # If folder doesn't exist, create it
        if not os.path.exists(folder):
            os.makedirs(folder)
        
        # Ensure data is in string format
        if isinstance(data, dict):
            data_str = json.dumps(data, ensure_ascii=False, indent=2)
        else:
            data_str = str(data)
            
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(data_str)



    def parse_text_with_images(self, content, source_dir, txt_file_name):
        """Parse text content containing image references and return message list in correct order"""
        messages = []
        
        # Split content by lines to preserve order
        lines = content.split('\n')
        current_text_parts = []
        
        for line in lines:
            if line.strip().startswith('image:'):
                # Before processing image, add accumulated text if any
                if current_text_parts:
                    text_content = '\n'.join(current_text_parts).strip()
                    if text_content:
                        messages.append({
                            "type": "text",
                            "text": text_content
                        })
                    current_text_parts = []
                
                # Process image
                image_path = line.strip().replace('image:', '').strip()
                
                # Replace the old path prefix with new one - only replace the specific prefix
                if image_path.startswith('D:/Desktop/malware/'):
                    image_path = image_path.replace('D:/Desktop/malware/', '/Users/blue/Documents/Github/')
                
                # Normalize path separators for the current system
                image_path = image_path.replace('\\', '/')
                
                print(f"Looking for image: {image_path}")
                
                if os.path.exists(image_path):
                    base64_image = self.encode_image(image_path)
                    if base64_image:
                        messages.append({
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{base64_image}"
                            }
                        })
                    else:
                        messages.append({
                            "type": "text",
                            "text": f"[Image encoding failed: {os.path.basename(image_path)}]"
                        })
                else:
                    messages.append({
                        "type": "text", 
                        "text": f"[Image not found: {image_path}]"
                    })
            else:
                # Accumulate text lines
                current_text_parts.append(line)
        
        # Add any remaining text at the end
        if current_text_parts:
            text_content = '\n'.join(current_text_parts).strip()
            if text_content:
                messages.append({
                    "type": "text",
                    "text": text_content
                })
        
        # If no messages were created, add the whole content as text
        if not messages:
            messages.append({
                "type": "text",
                "text": content
            })
        
        # Wrap in the role structure that the API expects
        if messages:
            return [{
                "role": "user", 
                "content": messages
            }]
        return []


    # Complete the entire process from entity extraction to information verification and save results
    # Stage 1: Relevance Analysis
    def related_analysis(self, content, source_dir, txt_file_name):
        """Stage 1: Relevance Analysis - Use only plain text content, remove image markers"""
        print(f"\n=== Stage 1: Relevance Analysis ===")
        print(f"Processing file: {txt_file_name}")
        # Print full path for debugging
        full_txt_path = os.path.join(self.content_dir, source_dir, txt_file_name)
        print(f"Full file path: {full_txt_path}")
        
        # Stage 1 uses only plain text, remove all image markers
        clean_content = re.sub(r'image:\s*[^\s\n]+', '', content).strip()
        
        # Build prompt message - use only cleaned text content
        prompt_message = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in analyzing malicious packages and code. Your task is to analyze the relevance of the given content and extract preliminary information."},
            {"role": "user", "content": self.intelli_related_prompt.replace("{INPUT_TEXT}", clean_content)}
        ]

        try:
            # Use small model for relevance analysis
            response = self.small_model_agent.perform_query(prompt_message)
            print(f"Relevance analysis completed (using small model)")
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            return {"error": "JSON parsing failed", "raw_response": response}
        except Exception as e:
            print(f"API call error: {e}")
            return {"error": "API call failed", "details": str(e)}
    
    # Stage 2: Entity Extraction
    def entity_extract(self, content, related_info, source_dir, txt_file_name):
        """Stage 2: Entity Extraction - Parse images and organize text and image content in sequence"""
        print(f"\n=== Stage 2: Entity Extraction ===")
        print(f"Processing file: {txt_file_name}")
        # Print full path for debugging
        full_txt_path = os.path.join(self.content_dir, source_dir, txt_file_name)
        print(f"Full file path: {full_txt_path}")
        
        # Use parse_text_with_images to parse content containing images
        messages_with_images = self.parse_text_with_images(content, source_dir, txt_file_name)
        
        # Build complete prompt message
        prompt_messages = [
            {"role": "system", "content": self.intelli_extract_prompt}
        ]
        
        # Add content containing images
        if messages_with_images:
            prompt_messages.extend(messages_with_images)
        
        try:
            # Use large model for entity extraction
            response = self.large_model_agent.perform_query(prompt_messages)
            print(f"Entity extraction completed (using large model)")
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            return {"error": "JSON parsing failed", "raw_response": response}
        except Exception as e:
            print(f"API call error: {e}")
            return {"error": "API call failed", "details": str(e)}
    
    # Stage 3: Information Verification
    def info_verify(self, content, extracted_entities, source_dir, txt_file_name):
        """Stage 3: Information Verification - Use Stage 2 LLM output results for verification"""
        print(f"\n=== Stage 3: Information Verification ===")
        print(f"Processing file: {txt_file_name}")
        # Print full path for debugging
        full_txt_path = os.path.join(self.content_dir, source_dir, txt_file_name)
        print(f"Full file path: {full_txt_path}")
        
        # Convert Stage 2 output results to string
        entities_str = json.dumps(extracted_entities, ensure_ascii=False, indent=2)
        
        # Build verification prompt, mainly using Stage 2 output results
        verification_prompt = self.intelli_verify_prompt.replace("{EXTRACTED_ENTITIES}", entities_str)
        
        # Build prompt message
        prompt_messages = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in verifying the accuracy of extracted information about malicious code detection."},
            {"role": "user", "content": [{"type": "text", "text": verification_prompt}]}
        ]
        
        try:
            # Use large model for information verification
            response = self.large_model_agent.perform_query(prompt_messages)
            print(f"Information verification completed (using large model)")
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            return {"error": "JSON parsing failed", "raw_response": response}
        except Exception as e:
            print(f"API call error: {e}")
            return {"error": "API call failed", "details": str(e)}

    def process_content(self, content, source_dir, txt_file_name):
        """Three-stage processing workflow"""
        # Extract base name from txt filename (remove .txt extension)
        base_name = txt_file_name.replace(".txt", "")
        
        # Create save directory: Dataset/IntelliJson/source/txt_folder/
        save_dir = os.path.join(self.json_dir, source_dir, base_name)
        
        # Extract and convert image paths
        image_paths = self.extract_and_convert_image_paths(content)
        
        # Save image path information
        if image_paths:
            image_paths_file = os.path.join(save_dir, "image_paths.json")
            self.save_json(image_paths, image_paths_file)
            print(f"Found {len(image_paths)} image paths, saved to {image_paths_file}")
        
        # Stage 1: Relevance Analysis
        print(f"Stage 1: Relevance analysis...")
        related_result = self.related_analysis(content, source_dir, txt_file_name)
        related_path = os.path.join(save_dir, "related.json")
        self.save_json(related_result, related_path)
        print(f"Relevance analysis results saved to: {related_path}")
        
        # Check if relevant, only relevant content proceeds to next stage
        if isinstance(related_result, dict) and related_result.get("is_relevant") == True:
            print("Content determined as relevant, proceeding with entity extraction...")
            
            # Stage 2: Entity Extraction
            print(f"Stage 2: Entity extraction...")
            extract_result = self.entity_extract(content, related_result, source_dir, txt_file_name)
            extract_path = os.path.join(save_dir, "extract.json")
            self.save_json(extract_result, extract_path)
            print(f"Entity extraction results saved to: {extract_path}")
            
            # Stage 3: Information Verification
            print(f"Stage 3: Information verification...")
            verify_result = self.info_verify(content, extract_result, source_dir, txt_file_name)
            verify_path = os.path.join(save_dir, "verify.json")
            self.save_json(verify_result, verify_path)
            print(f"Verification results saved to: {verify_path}")
            
        else:
            print("Content determined as irrelevant or analysis error, skipping further processing")
            if "error" in str(related_result):
                print(f"Relevance analysis error: {related_result}")
            else:
                print(f"Relevance analysis result: {related_result}")
        
        print(f"Processing completed: {source_dir}/{txt_file_name}\n")

    # Start execution
    def start(self, source_dir):
        self.source_dir = source_dir  # Set source directory
        
        # Build content directory path
        content_source_dir = os.path.join(self.content_dir, source_dir)
        
        # Check if directory exists
        if not os.path.exists(content_source_dir):
            print(f"Source directory does not exist: {content_source_dir}")
            return
            
        # Traverse all files in source directory
        for file_name in os.listdir(content_source_dir):
            # Skip hidden files and non-txt files
            if file_name.startswith('.') or not file_name.endswith('.txt'):
                print(f"\nSkipping: {file_name}")
                continue
            
            # Check if already processed (verify.json exists)
            base_name = file_name.replace(".txt", "")
            verify_path = os.path.join(self.json_dir, source_dir, base_name, "verify.json")
            
            if os.path.exists(verify_path):
                print(f"\n⊘ Skipped: {source_dir}/{file_name} (already processed)")
                continue
                
            # Read text content
            txt_file_path = os.path.join(content_source_dir, file_name)
            txt_content = self.read_txt(txt_file_path)
            
            print(f"\nProcessing: {source_dir}/{file_name}")
            print(f"Full file path: {txt_file_path}")
            
            # Process content using new three-stage workflow
            self.process_content(txt_content, source_dir, file_name)


if __name__ == '__main__':
    # Usage example
    ltmgpt = IntelliLLM()
    ltmgpt.start("bleepingcomputer")
    ltmgpt.start("sonatype")
    ltmgpt.start("checkmarx")
    ltmgpt.start("medium")
    ltmgpt.start("qianxin")
    ltmgpt.start("datadoghq")
    ltmgpt.start("snyk")