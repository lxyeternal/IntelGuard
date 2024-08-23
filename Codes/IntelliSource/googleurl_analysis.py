# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : googleurl_analysis.py
# @Project  : PMonitor
# Time      : 2023/11/29 15:39
# Author    : honywen
# version   : python 3.8
# Description：
"""


import re
import sys
import csv
import tldextract
from urllib.parse import urlparse
from collections import defaultdict
from datetime import datetime

csv.field_size_limit(sys.maxsize)


class GoogleUrlAnalysis:
    def __init__(self):
        self.flag = "1"
        # self.google_source_path = "../csv/google_source.csv"
        self.google_source_path = "../../csv/google_source.csv"
        self.ignore_ends = [".", "@", "/", "#", ".py", "wsr.", "mailto:", ".pdf", "javascript:", ".sh", "?", "**"]
        self.csvfile_content = list()

    def should_ignore(self, string):
        return any(string.endswith(end) or string.startswith(end) for end in self.ignore_ends)


    # def extract_domain(self, url):
    #     """从URL中提取域名"""
    #     try:
    #         parsed_url = urlparse(url)
    #         return parsed_url.netloc
    #     except ValueError:
    #         print(f"Warning: Unable to parse URL '{url}'")
    #         return ""


    def extract_domain(self, url):
        """从URL中提取主域名"""
        try:
            extracted = tldextract.extract(url)
            # 合并主域名和顶级域名
            main_domain = "{}.{}".format(extracted.domain, extracted.suffix)
            return main_domain
        except ValueError:
            print(f"Warning: Unable to parse URL '{url}'")
            return ""


    def find_date(self, text):
        # 正则表达式匹配 "Feb 22, 2023" 这样的日期格式
        pattern = r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2}),\s+(\d{4})\b'
        match = re.search(pattern, text)
        if match:
            # 将找到的日期转换为 datetime 对象
            date_str = f"{match.group(1)} {match.group(2)} {match.group(3)}"
            date_obj = datetime.strptime(date_str, "%b %d %Y")
            # 将日期格式化为 YYYY/MM/DD
            return date_obj.strftime("%Y/%m/%d")
        else:
            return None

    def read_csvfile(self):
        with open(self.google_source_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                self.csvfile_content.append(row)

    def count_url(self):
        domain_counts_by_manager = defaultdict(lambda: defaultdict(int))
        all_domain_counts = defaultdict(int)
        for row in self.csvfile_content:
            manager = row[0].strip()
            first_url = row[4]
            # second_url = row[5]
            first_url_domain = self.extract_domain(first_url)
            if first_url_domain:
                domain_counts_by_manager[manager][first_url_domain] += 1
                all_domain_counts[first_url_domain] += 1
            if self.flag == "2":
                second_urls = row[8]
                second_urls = eval(second_urls)
                for link in second_urls:
                    link = link.strip()
                    if self.should_ignore(link):
                        continue
                    second_domain = self.extract_domain(link)
                    if second_domain == first_url_domain:
                        continue
                    if not second_domain:  # If the domain is missing, use the main_domain
                        continue
                    domain_counts_by_manager[manager][second_domain] += 1
                    all_domain_counts[second_domain] += 1
            # 输出按manager分类的域名计数结果
        output_data = []
        for domain, count in all_domain_counts.items():
            if count > 10:
                manager_counts = {manager: domain_counts_by_manager[manager].get(domain, 0)
                                  for manager in domain_counts_by_manager if
                                  domain in domain_counts_by_manager[manager]}
                output_data.append([domain, manager_counts])
        for manager, domain_counts in domain_counts_by_manager.items():
            sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
            print(f"Domains for manager: {manager}")
            for domain, count in sorted_domains:
                if count > 10:
                    print(f"{domain}: {count}")
            print("-" * 50)

        # This will store the final output.
        final_dict = {}
        domain_list = ["phylum.io", "github.com", "reddit.com", "sonatype.com", "fortinet.com", "datadoghq.com", "medium.com", "checkmarx.com", "bleepingcomputer.com", "checkpoint.com",
                       "cybersecuritynews.com", "jfrog.com", "phylum.io", "qianxin.com", "reddit.com", "reversinglabs.com", "rhisac.org", "securityaffairs.com", "snyk.io",
                       "socket.io", "sonatype.com", "tuxcare.com", "twitter.com", "ycombinator.com"]
        # Iterate over each package manager in the dictionary.
        for package_manager, domains in domain_counts_by_manager.items():
            for domain, count in domains.items():
                if domain in domain_list:
                    # If the domain is not in the final_dict, initialize it.
                    if domain not in final_dict:
                        final_dict[domain] = {}
                    # Add the count to the correct package manager.
                    final_dict[domain][package_manager] = final_dict[domain].get(package_manager, 0) + count

        # Convert the dictionary to the specified list format.
        final_list = [[key, value] for key, value in final_dict.items()]
        print(final_list)

            # 输出所有URL的域名计数结果
        sorted_all_domains = sorted(all_domain_counts.items(), key=lambda x: x[1], reverse=True)
        # print(f"Domains for all URLs:")
        # for domain, count in sorted_all_domains:
        #     if count > 50:
        #         print(f"{domain}: {count}")

    def date_format(self):
        for row in self.csvfile_content:
            web_content = row[6]
            date = self.find_date(web_content)
            row.append(date)
            self.write_csvfile(row)


class GoogleSecondUrl:
    def __init__(self):
        self.flag = "2"
        self.google_source_path = "../Backtrace/oss_source/processed_files.csv"
        self.ignore_ends = [".", "@", "/", "#", ".py", "wsr.", "mailto:", ".pdf", "javascript:", ".sh", "?", "**"]
        self.csvfile_content = list()

    def should_ignore(self, string):
        return any(string.endswith(end) or string.startswith(end) for end in self.ignore_ends)

    def read_csvfile(self):
        with open(self.google_source_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                self.csvfile_content.append(row)

    # def extract_domain(self, url):
    #     """从URL中提取域名"""
    #     try:
    #         parsed_url = urlparse(url)
    #         return parsed_url.netloc
    #     except ValueError:
    #         print(f"Warning: Unable to parse URL '{url}'")
    #         return ""


    def extract_domain(self, url):
        """从URL中提取主域名"""
        try:
            extracted = tldextract.extract(url)
            # 合并主域名和顶级域名
            main_domain = "{}.{}".format(extracted.domain, extracted.suffix)
            return main_domain
        except ValueError:
            print(f"Warning: Unable to parse URL '{url}'")
            return ""


    def count_url(self):
        domain_counts_by_manager = defaultdict(lambda: defaultdict(int))
        all_domain_counts = defaultdict(int)
        for index, row in enumerate(self.csvfile_content):
            manager = "oss"
            source = row[1].strip()
            first_url = row[0]
            first_url_domain = self.extract_domain(first_url)
            if first_url_domain:
                domain_counts_by_manager[manager][first_url_domain] += 1
                all_domain_counts[first_url_domain] += 1
            if self.flag == "2":
                second_urls = row[2]
                second_urls = eval(second_urls)
                for link in second_urls:
                    link = link.strip()
                    if self.should_ignore(link):
                        continue
                    second_domain = self.extract_domain(link)
                    # if second_domain == first_url_domain:
                    #     continue
                    if not second_domain:  # If the domain is missing, use the main_domain
                        continue
                    domain_counts_by_manager[manager][second_domain] += 1
                    all_domain_counts[second_domain] += 1
            # 输出按manager分类的域名计数结果
        output_data = []
        for domain, count in all_domain_counts.items():
            if count > 10:
                manager_counts = {manager: domain_counts_by_manager[manager].get(domain, 0)
                                  for manager in domain_counts_by_manager if
                                  domain in domain_counts_by_manager[manager]}
                output_data.append([domain, manager_counts])
        sorted_all_domains = sorted(all_domain_counts.items(), key=lambda x: x[1], reverse=True)
        print(f"Domains for all URLs:")
        for domain, count in sorted_all_domains:
            if count > 5:
                print(f"{domain}: {count}")


import csv
from urllib.parse import urlparse
from collections import Counter


def extract_domain(url):
    # 提取一级域名
    try:
        parsed_url = urlparse(url)
        domain_parts = parsed_url.netloc.split('.')
        if len(domain_parts) > 1:
            return f"{domain_parts[-2]}.{domain_parts[-1]}"
    except:
        return None


def process_csv(file_path):
    domain_counts = Counter()  # 使用 Counter 来计数域名

    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # 跳过标题行（如果有的话）
        for row in reader:
            if len(row) > 4:  # 确保每行有足够的列
                url = row[4]
                domain = extract_domain(url)
                if domain:
                    domain_counts[domain] += 1

    # 按次数排序
    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
    return domain_counts, sorted_domains


# # 替换为你的文件路径
# file_path = '/Users/blue/Documents/GitHub/SCC_Intelligence/csv/google_source_raw.csv'
# domain_counts, resulting_domains = process_csv(file_path)
#
# # 打印排序后的域名和对应的计数
# for domain, count in resulting_domains:
#     print(f"{domain}: {count}")
#
# # 打印唯一域名的总数
# print(f"Total unique domains: {len(domain_counts)}")


def analysis_1():
    pkgname = {}
    with open("/Users/blue/Documents/GitHub/SCC_Intelligence/csv/google_source_raw.csv", newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # 跳过标题行（如果有的话）
        for row in reader:
            name = row[1]
            link_index = row[2]
            if name not in pkgname:
                pkgname[name] = []
            pkgname[name].append(link_index)
    max_values = [max(values, key=int) for values in pkgname.values()]
    # 使用 Counter 来统计频率
    frequency = Counter(max_values)
    # 计算总数以便计算比例
    total_count = sum(frequency.values())
    # 计算每个元素的出现比例，并排序
    frequency_percentage = {key: (value / total_count) * 100 for key, value in frequency.items()}
    sorted_frequency = sorted(frequency_percentage.items(), key=lambda x: x[1], reverse=True)
    # 输出排序后的频率和比例
    for value, percent in sorted_frequency:
        print(f"Value {value} appears {frequency[value]} times, which is {percent:.2f}% of the total.")
    # 找出小于等于 "50" 的元素及其总计数
    count_le_50 = sum(count for value, count in frequency.items() if int(value) <= 50)

    # 计算小于等于 "50" 的元素的概率
    probability_le_50 = (count_le_50 / total_count) * 100

    print(f"The probability of values less than or equal to '50' is {probability_le_50:.2f}%.")


# analysis_1()

#
if __name__ == '__main__':
    googleurl_analysis = GoogleUrlAnalysis()
    googleurl_analysis.read_csvfile()
    googleurl_analysis.count_url()
    # googleurl_analysis.date_format()


    # google_second_url = GoogleSecondUrl()
    # google_second_url.read_csvfile()
    # google_second_url.count_url()