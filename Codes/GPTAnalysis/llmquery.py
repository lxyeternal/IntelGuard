
import os
import json
import time
import logging
import requests
import tiktoken
import openai
import numpy as np
import faiss
import re
from itertools import islice
from openai import AzureOpenAI
from typing import List, Dict, Tuple, Union, Optional
from tenacity import retry, wait_random_exponential, stop_after_attempt, retry_if_not_exception_type

class LLMAgent:
    def __init__(self):
        # 获取当前文件的绝对路径
        current_file = os.path.abspath(__file__)
        
        # 获取项目根目录 (当前文件在 Codes/GPTAnalysis/ 目录中，需要回退两级)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        
        # 构建配置文件路径
        config_path = os.path.join(project_root, 'Configs', 'llm_config.json')

        print(f"配置文件路径: {config_path}")
        print(f"配置文件是否存在: {os.path.exists(config_path)}")
        
        self.config_path = config_path
        
        self.config = self._load_config()
        
        self.query_type = self.config.get("query_type", "azure")
        self.reasoning_mode = self.config.get("reasoning_mode", False)
        
        self._init_clients()
        
        self.max_attempts = self.config.get("max_attempts", 5)
        self.max_token_length = self.config.get("max_token_length", 16000)
        
        self.dimension = self.config.get("embedding_dimension", 3072)
        self.embedding_model = self.config.get("embedding_model", "text-embedding-3-large")
        
        self.embedding_max_tokens = self.config.get("embedding_max_tokens", 7000)
        self.embedding_retries = self.config.get("embedding_retries", 5)
        self.embedding_wait_time = self.config.get("embedding_wait_time", 3)

        
        self.json_patterns = [
            r'```json\s*(\{.*?\})\s*```',
            r'```\s*(\{.*?\})\s*```',
            r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            r'Answer:\s*(\{.*?\})',
            r'Result:\s*(\{.*?\})',
            r'Final answer:\s*(\{.*?\})',
        ]
        
        self.reasoning_end_indicators = [
            "final answer:", "answer:", "result:", "conclusion:",
            "final result:", "output:", "response:", "solution:"
        ]
    
    def _load_config(self) -> Dict:
        print(f"正在加载配置文件: {self.config_path}")
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as file:
                    config = json.load(file)
                    print(f"成功加载配置文件，包含 {len(config)} 个配置项")
                    return config
            except Exception as e:
                print(f"加载配置文件时出错: {e}")
                logging.error(f"Error loading config from {self.config_path}: {e}")
                return {}
        else:
            print(f"配置文件未找到: {self.config_path}")
            logging.warning(f"Config file not found at {self.config_path}, using empty config")
            return {}
    
    def _init_clients(self):
        embedding_backend = self.config.get("embedding_backend", "azure")
        
        if embedding_backend == "azure" and 'azure_api_key' in self.config:
            self.embedding_client = AzureOpenAI(
                api_key=self.config["azure_api_key"],
                api_version=self.config.get("azure_api_version", "2024-02-01"),
                azure_endpoint=self.config["azure_api_base"]
            )
        elif embedding_backend == "openai" and 'openai_api_key' in self.config:
            self.embedding_client = openai.OpenAI(api_key=self.config['openai_api_key'])
        
        if self.query_type == 'azure':
            if 'azure_api_key' not in self.config:
                raise ValueError("Azure API key not found in config")
            self.azure_client = AzureOpenAI(
                api_key=self.config["azure_api_key"],
                api_version=self.config.get("azure_api_version", "2024-02-01"),
                azure_endpoint=self.config["azure_api_base"]
            )
            self.azure_model = self.config.get('azure_api_model', 'gpt-4')
            
        elif self.query_type == 'openai':
            if 'openai_api_key' not in self.config:
                raise ValueError("OpenAI API key not found in config")
            self.openai_model = self.config.get('openai_api_model', 'gpt-4')
            self.openai_client = openai.OpenAI(api_key=self.config['openai_api_key'])
            
        elif self.query_type == 'ollama':
            self.ollama_model = self.config.get('ollama_model', 'llama3')
            self.ollama_host = self.config.get('ollama_host', '127.0.0.1')
            self.ollama_port = self.config.get('ollama_port', 11434)
            
        elif self.query_type == 'xinference':
            self.xinference_model = self.config.get('xinference_model', 'llama3')
            self.xinference_api_base = self.config.get('xinference_api_base', 'http://localhost:9997/v1')
            self.xinference_api_key = self.config.get('xinference_api_key', 'dummy-key')
            openai.api_base = self.xinference_api_base
            openai.api_key = self.xinference_api_key
    
    def extract_json_from_reasoning_output(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        
        for pattern in self.json_patterns:
            matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
            if matches:
                json_candidate = matches[-1].strip()
                try:
                    json.loads(json_candidate)
                    logging.info("Successfully extracted JSON from reasoning output using pattern")
                    return json_candidate
                except json.JSONDecodeError:
                    continue
        
        text_lower = text.lower()
        best_start = -1
        
        for indicator in self.reasoning_end_indicators:
            pos = text_lower.rfind(indicator)
            if pos > best_start:
                best_start = pos + len(indicator)
        
        if best_start > 0:
            remaining_text = text[best_start:].strip()
            for pattern in self.json_patterns:
                matches = re.findall(pattern, remaining_text, re.DOTALL)
                if matches:
                    json_candidate = matches[0].strip()
                    try:
                        json.loads(json_candidate)
                        logging.info("Successfully extracted JSON after reasoning indicators")
                        return json_candidate
                    except json.JSONDecodeError:
                        continue
        
        try:
            json_objects = []
            brace_count = 0
            start_pos = -1
            
            for i, char in enumerate(text):
                if char == '{':
                    if brace_count == 0:
                        start_pos = i
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_pos >= 0:
                        json_candidate = text[start_pos:i+1]
                        try:
                            json.loads(json_candidate)
                            json_objects.append(json_candidate)
                        except json.JSONDecodeError:
                            pass
                        start_pos = -1
            
            if json_objects:
                logging.info("Successfully extracted JSON using brace matching")
                return json_objects[-1]
                
        except Exception as e:
            logging.warning(f"Error in JSON extraction: {e}")
        
        logging.warning("Could not extract JSON from reasoning output, returning original text")
        return text
    
    def enhance_prompt_for_reasoning_model(self, messages: List[Dict[str, str]], require_json: bool = True) -> List[Dict[str, str]]:
        if not require_json:
            return messages
        
        enhanced_messages = messages.copy()
        
        json_instruction = """

IMPORTANT: After your reasoning process, you must provide your final answer in valid JSON format. 
End your response with:

Final Answer: {your_json_here}

Make sure the JSON is properly formatted and valid."""
        
        if enhanced_messages and enhanced_messages[-1]["role"] == "user":
            original_content = enhanced_messages[-1]["content"]
            enhanced_messages[-1]["content"] = original_content + json_instruction
        
        return enhanced_messages
    
    def count_tokens(self, content: str, model: str = None) -> int:
        if model is None:
            model = self.config.get("token_counting_model", "gpt-3.5-turbo-16k-0613")
        
        content = str(content)
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            logging.warning(f"Model {model} not found. Using cl100k_base encoding.")
            encoding = tiktoken.get_encoding("cl100k_base")
        
        return len(encoding.encode(content))
    
    def token_slice(self, content: str, token_limit: int = None) -> List[str]:
        if token_limit is None:
            token_limit = self.config.get("token_slice_limit", 14000)
        
        encoding_model = self.config.get("token_counting_model", "gpt-3.5-turbo-16k-0613")
        encoding = tiktoken.encoding_for_model(encoding_model)
        content_tokens = encoding.encode(content)
        
        segments = []
        current_segment = []
        current_length = 0
        
        for token in content_tokens:
            if current_length + 1 > token_limit:
                segments.append(encoding.decode(current_segment))
                current_segment = [token]
                current_length = 1
            else:
                current_segment.append(token)
                current_length += 1
                
        if current_segment:
            segments.append(encoding.decode(current_segment))
            
        return segments
    
    def perform_query(self, 
                     messages: List[Dict[str, str]], 
                     max_tokens: int = None,
                     temperature: float = None,
                     top_p: float = None,
                     frequency_penalty: float = None,
                     presence_penalty: float = None,
                     response_format: Optional[Dict] = None,
                     seed: int = None,
                     reasoning_effort: str = None,
                     extract_json: bool = None) -> str:
        max_tokens = max_tokens or self.config.get("default_max_tokens", 16000)
        temperature = temperature if temperature is not None else self.config.get("default_temperature", 0)
        top_p = top_p if top_p is not None else self.config.get("default_top_p", 0.3)
        frequency_penalty = frequency_penalty if frequency_penalty is not None else self.config.get("default_frequency_penalty", 0)
        presence_penalty = presence_penalty if presence_penalty is not None else self.config.get("default_presence_penalty", 0)
        seed = seed if seed is not None else self.config.get("default_seed", 42)
        reasoning_effort = reasoning_effort or self.config.get("default_reasoning_effort", "medium")
        extract_json = extract_json if extract_json is not None else self.config.get("default_extract_json", True)
        
        is_reasoning = self.reasoning_mode
        
        if is_reasoning and extract_json:
            messages = self.enhance_prompt_for_reasoning_model(messages, True)
        
        if not is_reasoning and response_format is None:
            auto_json_response = self.config.get("auto_json_response", True)
            if auto_json_response and self.query_type in ['openai', 'azure']:
                response_format = {"type": "json_object"}

        if self.query_type == "azure":
            result = self._azure_query(messages, max_tokens, temperature, top_p, 
                                     frequency_penalty, presence_penalty, response_format, seed, reasoning_effort)
        elif self.query_type == "ollama":
            result = self._ollama_query(messages, max_tokens, temperature, top_p, 
                                      frequency_penalty, presence_penalty, response_format, seed, reasoning_effort)
        elif self.query_type == "openai":
            result = self._openai_query(messages, max_tokens, temperature, top_p, 
                                      frequency_penalty, presence_penalty, response_format, seed, reasoning_effort)
        elif self.query_type == "xinference":
            result = self._xinference_query(messages, max_tokens, temperature, top_p, 
                                          frequency_penalty, presence_penalty, response_format, seed, reasoning_effort)
        else:
            raise ValueError(f"Unknown query type: {self.query_type}")
        
        if is_reasoning and extract_json and isinstance(result, str):
            result = self.extract_json_from_reasoning_output(result)
        
        return result
    
    def _get_current_model(self) -> str:
        if self.query_type == "azure":
            return self.azure_model
        elif self.query_type == "openai":
            return self.openai_model
        elif self.query_type == "ollama":
            return self.ollama_model
        elif self.query_type == "xinference":
            return self.xinference_model
        return ""
    
    def _prepare_reasoning_params(self, temperature: float, top_p: float, 
                                frequency_penalty: float, presence_penalty: float, 
                                max_tokens: int, reasoning_effort: str) -> Dict:
        params = {}
        
        if self.reasoning_mode:
            logging.info(f"Using reasoning mode with effort: {reasoning_effort}")
            
            params["max_completion_tokens"] = max_tokens
            params["reasoning_effort"] = reasoning_effort
            
                
        else:
            params.update({
                "temperature": temperature,
                "top_p": top_p,
                "frequency_penalty": frequency_penalty,
                "presence_penalty": presence_penalty,
                "max_tokens": max_tokens
            })
        
        return params
    
    def _azure_query(self, messages, max_tokens, temperature, top_p, frequency_penalty, 
                    presence_penalty, response_format, seed, reasoning_effort="medium"):
        wait_time = self.config.get("retry_wait_time", 10)
        wait_increment = self.config.get("retry_wait_increment", 5)
        attempt = 0
        
        while attempt < self.max_attempts:
            try:
                completion_params = {
                    "model": self.azure_model,
                    "messages": messages,
                    "stream": False
                }
                
                if self.reasoning_mode:
                    completion_params.update({
                        "max_completion_tokens": max_tokens,
                        "reasoning_effort": reasoning_effort
                    })
                else:
                    completion_params.update({
                        "temperature": temperature,
                        "top_p": top_p,
                        "frequency_penalty": frequency_penalty,
                        "presence_penalty": presence_penalty,
                        "max_tokens": max_tokens,
                        "seed": seed,
                        "stop": None
                    })
                    if response_format:
                        completion_params["response_format"] = response_format
                
                completion = self.azure_client.chat.completions.create(**completion_params)
                return completion.choices[0].message.content
                    
            except Exception as e:
                logging.warning(f"Attempt {attempt + 1}: An error occurred: {e}")
                attempt += 1
                time.sleep(wait_time)
                wait_time += wait_increment
        
        return ""
    
    def _openai_query(self, messages, max_tokens, temperature, top_p, frequency_penalty, 
                     presence_penalty, response_format, seed, reasoning_effort="medium"):
        wait_time = self.config.get("retry_wait_time", 10)
        wait_increment = self.config.get("retry_wait_increment", 5)
        attempt = 0
        
        while attempt < self.max_attempts:
            try:
                completion_params = {
                    "model": self.openai_model,
                    "messages": messages,
                    "stream": False
                }
                
                if self.reasoning_mode:
                    completion_params.update({
                        "max_completion_tokens": max_tokens,
                        "reasoning_effort": reasoning_effort
                    })
                else:
                    completion_params.update({
                        "temperature": temperature,
                        "top_p": top_p,
                        "frequency_penalty": frequency_penalty,
                        "presence_penalty": presence_penalty,
                        "max_tokens": max_tokens,
                        "seed": seed
                        # "stop": None
                    })
                    if response_format:
                        completion_params["response_format"] = response_format

                response = self.openai_client.chat.completions.create(**completion_params)
                return response.choices[0].message.content
                    
            except Exception as e:
                logging.warning(f"Attempt {attempt + 1}: An error occurred: {e}")
                attempt += 1
                time.sleep(wait_time)
                wait_time += wait_increment
        
        return ""
    
    def _ollama_query(self, messages, max_tokens, temperature, top_p, frequency_penalty, 
                     presence_penalty, response_format, seed, reasoning_effort="medium"):
        wait_time = self.config.get("retry_wait_time", 10)
        wait_increment = self.config.get("retry_wait_increment", 5)
        attempt = 0
        
        url = f"http://{self.ollama_host}:{self.ollama_port}/api/chat"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.ollama_model,
            "stream": False,
            "messages": messages,
        }
        
        if self.reasoning_mode:
            payload["options"] = {
                "num_ctx": self.config.get("ollama_context_size", 65536)
            }
        else:
            payload["options"] = {
                "temperature": temperature,
                "seed": seed,
                "num_ctx": self.config.get("ollama_context_size", 65536)
            }
            if response_format:
                payload["format"] = "json"
        
        while attempt < self.max_attempts:
            try:
                response = requests.post(url, headers=headers, data=json.dumps(payload))
                response.raise_for_status()
                return response.json()['message']['content']
            except Exception as e:
                logging.warning(f"Attempt {attempt + 1}: An error occurred: {e}")
                attempt += 1
                time.sleep(wait_time)
                wait_time += wait_increment
        
        return ""
    
    def _xinference_query(self, messages, max_tokens, temperature, top_p, frequency_penalty, 
                         presence_penalty, response_format, seed, reasoning_effort="medium"):
        wait_time = self.config.get("retry_wait_time", 10)
        wait_increment = self.config.get("retry_wait_increment", 5)
        attempt = 0
        
        while attempt < self.max_attempts:
            try:
                if self.reasoning_mode:
                    response = openai.ChatCompletion.create(
                        model=self.xinference_model,
                        messages=messages,
                        max_tokens=max_tokens
                    )
                else:
                    response = openai.ChatCompletion.create(
                        model=self.xinference_model,
                        messages=messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        top_p=top_p,
                        frequency_penalty=frequency_penalty,
                        presence_penalty=presence_penalty,
                        stop=None
                    )
                
                return response.choices[0].message['content']
            except Exception as e:
                logging.warning(f"Attempt {attempt + 1}: An error occurred: {e}")
                attempt += 1
                time.sleep(wait_time)
                wait_time += wait_increment
        
        return ""
    
    def generate_embedding(self, text: str) -> np.ndarray:
        
        if not text or not isinstance(text, str) or text.strip() == "":
            print(f"Generating embedding for text: {text}")
            logging.warning("Invalid input text, returning zero vector")
            return np.zeros(self.dimension)
        
        backend = self.config.get("embedding_backend", "openai")
        max_tokens = self.config.get("embedding_max_tokens", 8191)
        encoding_name = "cl100k_base"
        
        def batched(iterable, n):
            if n < 1:
                raise ValueError('n must be at least one')
            it = iter(iterable)
            while (batch := tuple(islice(it, n))):
                yield batch
        
        def chunked_tokens(text, encoding_name, chunk_length):
            encoding = tiktoken.get_encoding(encoding_name)
            tokens = encoding.encode(text)
            chunks_iterator = batched(tokens, chunk_length)
            yield from chunks_iterator
        
        @retry(
            wait=wait_random_exponential(min=1, max=20), 
            stop=stop_after_attempt(6), 
            retry=retry_if_not_exception_type(Exception)
        )
        def get_single_embedding(tokens_list):
            try:
                if backend == "azure":
                    if not hasattr(self, 'embedding_client') or self.embedding_client is None:
                        raise ValueError("Azure embedding client not initialized")
                    response = self.embedding_client.embeddings.create(
                        input=tokens_list,
                        model=self.embedding_model,
                        dimensions=self.dimension
                    )
                elif backend == "openai":
                    if not hasattr(self, 'embedding_client') or self.embedding_client is None:
                        raise ValueError("OpenAI embedding client not initialized")
                    response = self.embedding_client.embeddings.create(
                        input=tokens_list,
                        model=self.embedding_model,
                        dimensions=self.dimension
                    )
                else:
                    raise ValueError(f"Unsupported backend: {backend}")
                
                return response.data[0].embedding
                
            except Exception as e:
                logging.error(f"API call failed: {e}")
                raise
        
        try:
            chunk_embeddings = []
            chunk_lens = []
            
            for chunk_tokens in chunked_tokens(text, encoding_name, max_tokens):
                embedding = get_single_embedding(list(chunk_tokens))
                chunk_embeddings.append(embedding)
                chunk_lens.append(len(chunk_tokens))
                
                logging.debug(f"Processed chunk: {len(chunk_tokens)} tokens")
            
            if not chunk_embeddings:
                logging.error("Failed to generate any embeddings")
                return np.zeros(self.dimension)
            
            chunk_embeddings = np.array(chunk_embeddings, dtype=np.float32)
            
            if len(chunk_embeddings) == 1:
                embedding = chunk_embeddings[0]
                return embedding / np.linalg.norm(embedding)
            
            weights = np.array(chunk_lens, dtype=np.float32)
            final_embedding = np.average(chunk_embeddings, axis=0, weights=weights)
            final_embedding = final_embedding / np.linalg.norm(final_embedding)
            
            logging.info(f"Successfully generated embedding: {len(chunk_embeddings)} chunks -> {len(final_embedding)} dimensions")
            return final_embedding
            
        except Exception as e:
            logging.error(f"Failed to generate embedding: {e}")
            return np.zeros(self.dimension)

if __name__ == "__main__":
    
    agent = LLMAgent()
    
    print(f"=== Current Configuration ===")
    print(f"Query Type: {agent.query_type}")
    print(f"Reasoning Mode: {agent.reasoning_mode}")
    print(f"Current Model: {agent._get_current_model()}")
    
    print(f"\n=== Embedding Test ===")
    test_text = "Python is a high-level, interpreted programming language with dynamic semantics."
    embedding = agent.generate_embedding(test_text)
    print(f"Text: {test_text}")
    print(f"Embedding shape: {embedding.shape}")
    print(f"Embedding norm: {np.linalg.norm(embedding):.6f}")
    
    print(f"\n=== LLM Query Test ===")
    test_messages = [
        {"role": "system", "content": "You are a useful assistant."},
        {"role": "user", "content": "Please introduce Python briefly, output format as JSON"}
    ]
    
    response = agent.perform_query(test_messages)
    print("Response:", response)