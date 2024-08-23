# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : main.py
# @Project  : IntelliRadar
# Time      : 13/8/24 9:42 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
from collections import defaultdict
from Codes.GPTAnalysis.lstgptuse import LTMGPT
from Codes.Aggregate.dataintegrity import DataIntegrity
from Codes.Collection.webpage_content import WebPageContent
from Codes.Collection.webpage_collection import WebPageCollection


class IntelligencePipeline:
    def __init__(self):
        self.current_dir = os.path.dirname(__file__)
        self.project_dir = os.path.dirname(self.current_dir)
        self.webpage_content = WebPageContent()  # 情报源相关的blog链接提取
        self.webpage_collection = WebPageCollection()  # 网页内容采集
        self.ltmgpt = LTMGPT()  # LLM情报实体提取
        self.dataintegrity = DataIntegrity()  # 情报实体聚合
        self.waiting_collection_file = os.path.join(self.current_dir, "Collection/pagelinks/waiting_collection.txt")
        self.collected_pagelinks_file = os.path.join(self.current_dir, "Collection/pagelinks/collected_pagelinks.txt")
        self.sources = defaultdict(list)

    def load_waiting_collection(self):
        """加载等待处理的链接并组织成字典格式 {source: [(timestamp, date, link)]}"""
        if not os.path.exists(self.waiting_collection_file):
            raise FileNotFoundError(f"{self.waiting_collection_file} not found.")
        with open(self.waiting_collection_file, 'r') as file:
            for line in file:
                timestamp, source, date, link = line.strip().split('\t')
                self.sources[source].append((timestamp, date, link))

    def extract_blogs(self):
        """执行博客提取任务"""
        self.webpage_collection.load_old_webpages()
        # Uncomment the lines below to run the actual blog collection process.
        # self.webpage_collection.snyk_blog()
        # self.webpage_collection.qianxin_blog()
        # self.webpage_collection.datadoghq_blog()
        # self.webpage_collection.jfrog_blog()
        # self.webpage_collection.github_blog()
        # self.webpage_collection.medium_recommand()
        # self.webpage_collection.medium_blog()
        # self.webpage_collection.checkmarx_blog()
        # self.webpage_collection.sonatype_oss_blog()
        # self.webpage_collection.sonatype_blog()
        # self.webpage_collection.bleepingcomputer_blog()
        # self.webpage_collection.securityaffairs_blog()
        # self.webpage_collection.fortinet_blog()
        # self.webpage_collection.phylum_blog()
        # self.webpage_collection.reversinglabs_blog()
        # self.webpage_collection.tuxcare_blog()
        # self.webpage_collection.cybersecuritynews_blog()
        # self.webpage_collection.rhisac_blog()
        # self.webpage_collection.socket_blog()
        # self.webpage_collection.checkpoint_blog()
        # self.webpage_collection.reddit_blog()

    def process_blogs(self):
        self.load_waiting_collection()
        """处理 waiting_collection.txt 中的博客"""
        for source, entries in self.sources.items():
            for entry in entries:
                timestamp, date, link = entry
                self.process_single_blog(source, timestamp, date, link)
                self.update_files(source, timestamp, date, link)

    def process_single_blog(self, source, timestamp, date, link):
        """处理单个博客链接"""
        print(f"Processing {source}: {link}")
        self.extract_webpage_content(source, timestamp, link)
        content_file_path = os.path.join(self.project_dir, "Dataset/Content/{source}/{timestamp}.txt".format(source=source, timestamp=timestamp))
        self.process_with_ltmgpt(source, content_file_path, f"{timestamp}.txt")
        json_file_path = os.path.join(self.project_dir, "Dataset/Json/{source}/{timestamp}_verify_gpt4.json".format(source=source, timestamp=timestamp))
        self.aggregate_json(source, json_file_path)

    def extract_webpage_content(self, source, timestamp, link):
        """提取网页内容"""
        extract_method = getattr(self.webpage_content, f"{source}_content", None)
        if callable(extract_method):
            extract_method(timestamp, link)
        else:
            raise NotImplementedError(f"No content extraction method for source: {source}")

    def process_with_ltmgpt(self, source, content_file_path, content_file_name):
        """调用 LLM 进行内容分析"""
        self.ltmgpt.process_content(source, content_file_path, content_file_name)

    def aggregate_json(self, source, json_file_path):
        """聚合解析后的 JSON 文件"""
        self.dataintegrity.process_files(source, json_file_path)

    def update_files(self, source, timestamp, date, link):
        """更新文件，将处理完成的链接从 waiting_collection.txt 删除并写入 collected_pagelinks.txt"""
        self.remove_from_waiting_collection(timestamp, source, date, link)
        self.append_to_collected_pagelinks(timestamp, source, date, link)

    def remove_from_waiting_collection(self, timestamp, source, date, link):
        """从 waiting_collection.txt 中删除已处理的链接"""
        lines_to_keep = []
        with open(self.waiting_collection_file, 'r') as file:
            for line in file:
                if line.strip() != f"{timestamp}\t{source}\t{date}\t{link}":
                    lines_to_keep.append(line)

        with open(self.waiting_collection_file, 'w') as file:
            file.writelines(lines_to_keep)

    def append_to_collected_pagelinks(self, timestamp, source, date, link):
        """将处理完成的链接追加到 collected_pagelinks.txt 中"""
        with open(self.collected_pagelinks_file, 'a') as file:
            file.write(f"{timestamp}\t{source}\t{date}\t{link}\n")

    def run_pipeline(self):
        """运行整个流程"""
        # self.extract_blogs()
        self.process_blogs()


# 示例用法
if __name__ == "__main__":
    pipeline = IntelligencePipeline()
    pipeline.run_pipeline()

