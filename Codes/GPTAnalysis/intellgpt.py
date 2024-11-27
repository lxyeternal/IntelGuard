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
import nltk
import base64
import openai  # 0.28.1
import tiktoken
from nltk.corpus import stopwords
# 首次使用时需要下载停用词集
nltk.download('stopwords')
# 获取英语停用词集xw
stop_words = set(stopwords.words('english'))


class IntelliLLM:
    def __init__(self):
        self.source_dir = ""
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.json_dir = os.path.join(project_dir, "Dataset", "IntelliJson")
        self.content_dir = os.path.join(project_dir, "Dataset", "Content")
        self.images_dir = os.path.join(project_dir, "Dataset", "Image")
        self.common_words_file = os.path.join(project_dir, "archive", "common_word.txt")
        self.all_entity_file = os.path.join(current_dir, "EntityRules", "all_entity")
        self.intelli_direct_prompt_path = os.path.join(current_dir, "LtM_prompts", "intelli_direct")
        self.info_verify_prompt_path = os.path.join(current_dir, "LtM_prompts", "intelli_entity_verify")
        self.functionality_file = os.path.join(current_dir, "EntityRules", "functionality_list")
        self.exoutput_file = os.path.join(current_dir, "Exoutput", "intelli_output2")
        self.intelli_direct_prompt = self.read_file(self.intelli_direct_prompt_path)
        self.infoverify_prompt = self.read_file(self.info_verify_prompt_path)
        self.all_entity = self.read_file(self.all_entity_file)
        self.functionality_list = self.read_file(self.functionality_file)
        self.exoutput = self.read_file(self.exoutput_file)
        self.common_words = set()
        self.regex = r"(?:@[a-zA-Z0-9\-]+\/)?[a-zA-Z0-9][a-zA-Z0-9\._\-]+"
        self.dealt_pkgs = list()
        self.max_attempts = 5  # 最大尝试次数
        self.config_path = os.path.join(os.path.dirname(__file__), "..", "..", "Configs", "config.json")
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

    def load_common_words(self):
        with open(self.common_words_file, 'r', encoding='utf-8') as file:
            for line in file:
                self.common_words.add(line.strip().lower())

    def encode_image(self, image_path):
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')


    def extract_package_names(self, content):
        # PyPI 和 npm 的正则表达式
        try:
            unique_words = list()
            matches = re.findall(self.regex, content)
            # 去除重复的匹配项
            unique_matches = set(matches)
            for word in unique_matches:
                if word.endswith(".") or word.endswith(","):
                    word = word[:-1]
                    if word.lower() not in self.common_words:
                        unique_words.append(word)
                else:
                    if word.lower() not in self.common_words:
                        unique_words.append(word)
            unique_words = set(unique_words)
            return unique_words
        except Exception as e:
            print(f"An error occurred: {e}")
            return set()

    # 读取处理过的包名文件列表
    def load_dealt_pkgs(self):
        target_dir = os.path.join(self.json_dir, self.source_dir)
        if not os.path.exists(target_dir):
            return
        self.dealt_pkgs = os.listdir(target_dir)
        self.dealt_pkgs = [json_file.replace("_easy_extract_gpt4.json", ".txt").replace("_complex_extract_gpt4.json", ".txt").replace("_verify_gpt4.json", ".txt") for json_file in self.dealt_pkgs if json_file != ".DS_Store"]

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

    def parse_text_with_images(self, content):
        content = content.replace('\\', '/')
        # print(content)
        messages = []
        # 正则匹配所有 image: 路径
        pattern = r'image:\s*([^\s]+)'
        parts = re.split(pattern, content)
        combined_content = []  # 用于存储组合后的 text 和 image_url

        for index, part in enumerate(parts):
            if index % 2 == 0:
                # 偶数索引是文本
                if part.strip():
                    combined_content.append({
                        "type": "text",
                        "text": part.strip()
                    })
            else:
                # 奇数索引是图片路径
                # image_rel_path = part.strip().replace('\\', '/')
                path_parts = part.strip().split('/')
                if len(path_parts) >= 2:
                    # 提取最后两个部分
                    new_rel_path = os.path.join(*path_parts[-2:])
                    # 拼接固定的基础路径
                    full_image_path = os.path.join(self.images_dir, self.source_dir, new_rel_path)
                    # 规范化路径
                    full_image_path = os.path.normpath(full_image_path)
                    # print(full_image_path)
                    if os.path.exists(full_image_path):
                        base64_image = self.encode_image(full_image_path)
                        if base64_image:
                            combined_content.append({
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{base64_image}"
                                }
                            })
                    else:
                        combined_content.append({
                            "type": "text",
                            "text": f"[图片不存在: {new_rel_path}]"
                        })
                else:
                    combined_content.append({
                        "type": "text",
                        "text": f"[无效的图片路径: {part}]"
                    })

        # 将组合后的文本和图片内容一起作为 "content" 发送
        if combined_content:
            messages.append({
                "role": "user",
                "content": combined_content
            })
        return messages

    # 提取复杂实体
    def entity_extract_llm(self, content, potential_entity):
        # print(potential_entity)
        # 统计 token 的数量
        token_length = self.num_tokens_from_messages(content)
        max_tokens = 110000 - int(1.0 * token_length)
        if token_length > 110000:
            content = self.token_slice(content)
        content_message = self.parse_text_with_images(content)
        # print(content_message)
        prompt_message = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in analyzing malicious package and malicious code in package managers. Your task is to extract specific entity information from the given content, focusing only on the entities defined in the entity description."},
            {"role": "user", "content": "[**entity description**]:\n" + self.all_entity + "\n\n[**functionality list**]:\n" + self.functionality_list + "\n\n[**potential malicious package name**]:\n" + str(potential_entity) + "\n\n" + "\n\n[**example output**]:\n" + self.exoutput + "\n\n" + self.intelli_direct_prompt}
        ]
        combined_message = content_message + prompt_message
        # 将数据写入到JSON文件，带有格式化
        # with open("test.json", "w", encoding="utf-8") as f:
        #     json.dump(combined_message, f, ensure_ascii=False, indent=4)
        complex_entity = self.azure_query(combined_message, max_tokens)
        return complex_entity

    # 验证提取的信息的准确性
    def info_verify_llm(self, content, complex_entity):
        # 统计 token 的数量
        token_length = self.num_tokens_from_messages(content)
        max_tokens = 110000 - int(1.0 * token_length)
        if token_length > 110000:
            content = self.token_slice(content)
        content_message = self.parse_text_with_images(content)
        prompt_message = [
            {"role": "system", "content": "You are a cybersecurity expert specializing in verifying the accuracy of extracted information about malicious code detection. Your task is to cross-check the extracted entities against the original content, ensuring all information is accurate and supported by the text."},
            {"role": "user", "content": "[**entity_items**]:\n\n" + complex_entity + "\n\n[**content**]:\n" + content + "\n\n" + self.infoverify_prompt}
        ]
        combined_message = content_message + prompt_message
        entity_validated = self.azure_query(combined_message, max_tokens)
        return entity_validated

    # 完成从提取实体到验证信息的整个流程，并保存结果
    def process_content(self, content, file_name):
        self.load_common_words()
        re_pkgnames = self.extract_package_names(content)
        # 删除停用词
        filtered_words = [word for word in re_pkgnames if word not in stop_words]
        complete_entity = self.entity_extract_llm(content, filtered_words)  # 调用 entity_extract_llm 提取复杂实体
        self.save_json(complete_entity, file_name + "_extract_gpt4.json")
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


if __name__ == '__main__':
    # 使用示例
    ltmgpt = IntelliLLM()
    # ltmgpt.start("test")
    ltmgpt.start("phylum")
    # ltmgpt.start("sonatype_oss")
    # ltmgpt.start("checkmarx")
    # ltmgpt.start("medium_recommand")
