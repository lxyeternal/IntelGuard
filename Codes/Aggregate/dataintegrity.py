# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : dataintegrity.py
# @Project  : PMonitor
# Time      : 18/1/24 2:59 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import csv
import json
from datetime import datetime


class DataIntegrity:
    def __init__(self):
        self.intellisource = ""
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.output_csv = os.path.join(project_dir, "Dataset/CSV", "integrity.csv")
        self.keys = ["Package Name", "Package Manager", "Version", "Discovery Date", "Repository URL", "Attack Method", "Discoverer", "Impacted Systems", "Attack Vector", "Indicators of Compromise", "Timestamp", "Source"]

    def remove_json_comments(self, json_string):
        lines = json_string.split('\n')
        # 处理可能的第一行和最后一行包含注释标记的情况
        if lines[0].strip() == "```json" and lines[-1].strip() == "```":
            cleaned_json_string = '\n'.join(lines[1:-1])
        else:
            cleaned_json_string = json_string
        return cleaned_json_string

    def parse_json_file(self, file_path):
        data_timestamp = self.parse_timestamp(file_path)
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()
            file_content = self.remove_json_comments(file_content)
            try:
                data = json.loads(file_content)
            except json.JSONDecodeError:
                print(file_path)
                return []

            # 如果 JSON 文件是空的，直接返回空列表
            if isinstance(data, list) and not data:
                return []

            parsed_data = []
            for item in data:
                package_names = item.get("Package Name", [])
                if not isinstance(package_names, list):
                    package_names = [package_names]

                for package_name in package_names:
                    method_of_attack = item.get("Method Attack", [])
                    if isinstance(method_of_attack, str):
                        method_of_attack = [method_of_attack]

                    data_of_discovery = item.get("Discovery Date", [])
                    if isinstance(data_of_discovery, str):
                        data_of_discovery = [data_of_discovery]

                    repository_url = item.get("Repository URL", [])
                    if isinstance(repository_url, str):
                        repository_url = [repository_url]

                    discoverer = item.get("Discoverer", [])
                    if isinstance(discoverer, str):
                        discoverer = [discoverer]

                    iocs = item.get("Indicators of Compromise", [])
                    if isinstance(iocs, str):
                        iocs = [iocs]

                    impacted_systems = item.get("Impacted Systems", [])
                    if isinstance(impacted_systems, str):
                        impacted_systems = [impacted_systems]

                    attack_vector = item.get("Attack Vector", [])
                    if isinstance(attack_vector, str):
                        attack_vector = [attack_vector]

                    parsed_entry = {
                        "Package Name": package_name,
                        "Package Manager": item.get("Package Manager", ""),
                        "Version": item.get("Version", ""),
                        "Discovery Date": ", ".join(data_of_discovery),
                        "Repository URL": ", ".join(repository_url),
                        "Attack Method": ", ".join(method_of_attack),
                        "Discoverer": ", ".join(discoverer),
                        "Impacted Systems": ", ".join(impacted_systems),
                        "Attack Vector": ", ".join(attack_vector),
                        "Indicators of Compromise": ", ".join(iocs),
                        "Timestamp": data_timestamp,
                        "Source": self.intellisource
                    }
                    parsed_data.append(parsed_entry)
            return parsed_data

    def write_to_csv(self, data):
        if not data:
            return
        file_exists = os.path.isfile(self.output_csv)
        with open(self.output_csv, 'a', newline='', encoding='utf-8') as file:
            dict_writer = csv.DictWriter(file, fieldnames=self.keys)
            if not file_exists:
                dict_writer.writeheader()
            dict_writer.writerows(data)


    def parse_timestamp(self, file_path):
        # 提取文件名
        file_name = os.path.basename(file_path)
        # 从文件名中提取日期部分（假设日期总是在文件名的开头且格式为YYYYMMDD）
        date_string = file_name[:8]
        # 将日期字符串转换为datetime对象
        date_object = datetime.strptime(date_string, "%Y%m%d")
        # 将datetime对象格式化为所需的输出格式
        formatted_date = date_object.strftime("%Y-%m-%d")
        return str(formatted_date)

    def process_files(self, intellisource, file_path):
        self.intellisource = intellisource
        parsed_data = self.parse_json_file(file_path)
        self.write_to_csv(parsed_data)


# if __name__ == '__main__':
#     dataintegrity = DataIntegrity()
#     dataintegrity.process_files("jfrog", "/Users/blue/Documents/IntelliRadar/Dataset/Json/jfrog/20240406_151844_572156_verify_gpt4.json")