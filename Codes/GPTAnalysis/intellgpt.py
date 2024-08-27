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
import time
import openai  # 0.28.1
import tiktoken


class IntelliLLM:
    def __init__(self):
        self.source_dir = ""
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.json_dir = os.path.join(project_dir, "Dataset", "IntelliJson")
        self.content_dir = os.path.join(project_dir, "Dataset", "Content")
        self.entity_file_easy = os.path.join(current_dir, "EntityRules", "intelli_entity-4")
        self.entity_file_complex = os.path.join(current_dir, "EntityRules", "intelli_entity-5")
        self.entity_easy_prompt_path = os.path.join(current_dir, "LtM_prompts", "intelli_easy_extract")
        self.entity_complex_prompt_path = os.path.join(current_dir, "LtM_prompts", "intelli_complex_extract")
        self.info_verify_prompt_path = os.path.join(current_dir, "LtM_prompts", "intelli_entity_verify")
        self.entity_easy_prompt = self.read_file(self.entity_easy_prompt_path)
        self.entity_complex_prompt = self.read_file(self.entity_complex_prompt_path)
        self.info_verify_prompt = self.read_file(self.info_verify_prompt_path)
        self.easy_entity = self.read_file(self.entity_file_easy)
        self.complex_entity = self.read_file(self.entity_file_complex)
        self.max_attempts = 5  # 最大尝试次数
        self.config_path = os.path.join(project_dir, "Configs", "config.json")
        with open(self.config_path, 'r') as file:
            self.config = json.load(file)
        openai.api_type = self.config['azure_api_type']
        openai.api_base = self.config['azure_api_base']
        openai.api_version = self.config['azure_api_version']
        openai.api_key = self.config['azure_api_key']

    # 读取提示文件内容
    def read_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content

    # 读取处理过的包名文件列表
    def load_dealt_pkgs(self):
        self.dealt_pkgs = os.listdir(os.path.join(self.json_dir, self.source_dir))
        self.dealt_pkgs = [json_file.replace("_verify_gpt4.json", ".txt").replace("_relation_gpt4.json", ".txt").replace("_extract_gpt4.json", ".txt") for json_file in self.dealt_pkgs if json_file != ".DS_Store"]


    @staticmethod
    def read_txt(file_name):
        with open(file_name, "r", encoding="utf-8") as f:
            content = f.read()
        return content

    @staticmethod
    def save_json(data, file_name):
        # 获取文件夹路径
        folder = os.path.dirname(file_name)
        # 如果文件夹不存在，则创建它
        if not os.path.exists(folder):
            os.makedirs(folder)
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(data)

    # 计算消息的token数量
    def num_tokens_from_messages(self, content, model="gpt-3.5-turbo-16k-0613"):
        """Return the number of tokens used by a list of messages."""
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            print("Warning: model not found. Using cl100k_base encoding.")
            encoding = tiktoken.get_encoding("cl100k_base")
        if model in {
            "gpt-3.5-turbo-0613",
            "gpt-3.5-turbo-16k-0613",
            "gpt-4-0314",
            "gpt-4-32k-0314",
            "gpt-4-0613",
            "gpt-4-32k-0613",
        }:
            pass
        elif model == "gpt-3.5-turbo-0301":
            pass
        elif "gpt-3.5-turbo" in model:
            print("Warning: gpt-3.5-turbo may update over time. Returning num tokens assuming gpt-3.5-turbo-0613.")
            return self.num_tokens_from_messages(content, model="gpt-3.5-turbo-0613")
        elif "gpt-4" in model:
            print("Warning: gpt-4 may update over time. Returning num tokens assuming gpt-4-0613.")
            return self.num_tokens_from_messages(content, model="gpt-4-0613")
        else:
            raise NotImplementedError(
                f"""num_tokens_from_messages() is not implemented for model {model}. See https://github.com/openai/openai-python/blob/main/chatml.md for information on how messages are converted to tokens.""")
        num_tokens = len(encoding.encode(content))
        return num_tokens

    # 将内容分割为多个片段以适应token限制
    def token_slice(self, content):
        encoding = tiktoken.encoding_for_model("gpt-3.5-turbo-16k-0613")
        content_tokens = encoding.encode(content)
        token_limit = 30000
        segments = []
        current_segment = []
        current_length = 0
        decode_segments = []
        for token in content_tokens:
            if current_length + 1 > token_limit:  # 达到或超过限制则开始新段
                segments.append(current_segment)
                current_segment = [token]
                current_length = 1
            else:
                current_segment.append(token)
                current_length += 1
        if current_segment:
            segments.append(current_segment)
        for segment in segments:
            segment_text = encoding.decode(segment)
            decode_segments.append(segment_text)
        return decode_segments[0]

    def azure_query(self, message_text, max_tokens):
        max_tokens = 16000
        wait_time = 10
        attempt = 0
        output = ""
        while attempt < self.max_attempts:
            try:
                completion = openai.ChatCompletion.create(
                    # engine="csl-malicious",
                    engine="csl-malicious-4o-mini",
                    messages=message_text,
                    response_format={"type": "json_object"},
                    temperature=0,
                    max_tokens=max_tokens,
                    top_p=0.3,
                    frequency_penalty=0,
                    presence_penalty=0,
                    stop=None
                )
                output = completion.choices[0].message['content']
                break  # 如果成功，跳出循环
            except Exception as e:
                print(f"Attempt {attempt + 1}: An error occurred: {e}")
                attempt += 1
                time.sleep(wait_time)
                wait_time += 5  # 每次失败后增加等待时间
        print(output)
        return output

    # 提取简单实体
    def easy_entity_llm(self, content):
        # 设置token
        token_length = self.num_tokens_from_messages(content)
        max_tokens = 110000 - int(1.0 * token_length)
        if token_length > 110000:
            content = self.token_slice(content)

        # # 构造发送给 ChatGPT 的消息文本
        # content 文本
        # images 图片
        # self.easy_entity 简单实体
        # self.entityextract_prompt1 提示词
        message_text = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in analyzing malicious code in package managers. Your task is to extract specific entity information from the given content, focusing only on the entities defined in the entity description."},
            {"role": "user", "content": "[**content**]:\n" + content + "\n\n[**entity description**]:\n" + self.easy_entity + "\n\n" + self.entity_easy_prompt + "\n\n"}  # prompt-4
        ]
        # 调用 azure_query 发送请求并获取提取的实体
        extracted_entity = self.azure_query(message_text, max_tokens)
        return extracted_entity

    # 提取复杂实体
    def complex_entity_llm(self, content, extracted_entity):
        # 统计 token 的数量
        token_length = self.num_tokens_from_messages(content)
        max_tokens = 110000 - int(1.0 * token_length)
        if token_length > 110000:
            content = self.token_slice(content)

        # content 文本
        # extracted_entity 提取出的简单实体
        # self.complex_entity 复杂实体
        # self.entityextract_prompt2 提示词
        message_text = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in analyzing malicious code in package managers. Your task is to extract specific entity information from the given content, focusing only on the entities defined in the entity description."},
            {"role": "user", "content": "[**content**]:\n" + content + "\n\n[**extracted entities**]:\n" + extracted_entity + "\n\n[**entity description**]:\n" + self.complex_entity + "\n\n" + self.entity_complex_prompt + "\n\n"}
        ]
        complex_entity = self.azure_query(message_text, max_tokens)
        return complex_entity

    # 验证提取的信息的准确性
    def info_verify_llm(self, content, entity):
        # 统计 token 的数量
        token_length = self.num_tokens_from_messages(content)
        max_tokens = 110000 - int(1.0 * token_length)
        if token_length > 110000:
            content = self.token_slice(content)
        # content, entity, infoverify_prompt
        message_text = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in verifying the accuracy of extracted information about malicious code detection. Your task is to cross-check the extracted entities and their relationships against the original content, ensuring all information is accurate and supported by the text."},
            {"role": "user", "content": "[**content**]:\n" + content + "\n\n[**simple entities**]:\n" + self.easy_entity + "\n\n[**entities**]:\n" + entity + "\n\n" + self.info_verify_prompt + "\n\n"}
        ]
        entity_validated = self.azure_query(message_text, max_tokens)
        return entity_validated

    # 完成从提取实体到验证信息的整个流程，并保存结果
    def process_content(self, content, file_name):
        easy_entities = self.easy_entity_llm(content)  # 调用 entity_extract_llm 提取简单实体
        self.save_json(easy_entities, file_name + "_easy_gpt4.json")  # 将提取的实体保存为_easyextract_gpt4格式的 JSON 文件
        complete_entity = self.complex_entity_llm(content, easy_entities)  # 提取复杂实体
        self.save_json(complete_entity, file_name + "_complex_gpt4.json")
        llm_verify = self.info_verify_llm(content, complete_entity)  # 验证
        self.save_json(llm_verify, file_name + "_verify_gpt4.json")

    # 启动执行
    def start(self, source_dir):
        self.source_dir = source_dir  # 设置源目录
        self.load_dealt_pkgs()  # 加载已处理的包名列表
        # 遍历源目录中所有文件，如果是隐藏文件或已经处理过，则跳过
        for file_name in os.listdir(os.path.join(self.content_dir, self.source_dir)):
            if (file_name in [".DS_Store"]) or (file_name in self.dealt_pkgs):
                print(f"Skipping: {file_name}")
                continue

            # 生成对应 JSON 文件路径
            json_file_name = file_name.replace(".txt", "")
            json_file_path = os.path.join(self.json_dir, self.source_dir, json_file_name)
            txt_content = self.read_txt(os.path.join(self.content_dir, self.source_dir, file_name))  # 读取文本内容
            print(f"Processing: {file_name}")
            self.process_content(txt_content, json_file_path)


    def case_test(self, source_dir):
        case_dir = "../../Dataset/Case/"
        # 遍历 Case 目录中所有文件
        for file_name in os.listdir(case_dir):
            # 生成对应 JSON 文件路径
            json_file_name = file_name.replace(".txt", "")
            json_file_path = os.path.join(self.json_dir, source_dir, json_file_name)
            txt_content = self.read_txt(os.path.join(case_dir, file_name))  # 读取文本内容
            print(f"Processing: {file_name}")
            self.process_content(txt_content, json_file_path)


if __name__ == '__main__':
    # 使用示例
    ltmgpt = IntelliLLM()
    ltmgpt.case_test("case")
