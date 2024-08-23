# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : source_analysis.py
# @Project  : PMonitor
# Time      : 2023/10/22 15:48
# Author    : honywen
# version   : python 3.8
# Description：
"""


import csv
import tldextract
from urllib.parse import urlparse
from collections import defaultdict


class SnykUrlAnalysis:
    def __init__(self):
        self.flag = "2"
        self.snyk_source_path = "../../csv/snykref_source.csv"
        self.ignore_ends = [".", "@", "/", "#", ".py", "wsr.", "mailto:", "javascript:", ".sh", "?", "**"]

    # def extract_domain(self, url):
    #     """从URL中提取域名"""
    #     try:
    #         parsed_url = urlparse(url)
    #         return parsed_url.netloc
    #     except ValueError:
    #         print(f"Warning: Unable to parse URL '{url}'")
    #         return ""

    def should_ignore(self, string):
        return any(string.endswith(end) or string.startswith(end) for end in self.ignore_ends)

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

    def analyze_urls(self):
        """分析按manager划分的域名出现的次数"""
        domain_counts_by_manager = defaultdict(lambda: defaultdict(int))
        all_domain_counts = defaultdict(int)

        with open(self.snyk_source_path, encoding="ISO-8859-1") as csvfile:
            csv_reader = csv.reader(csvfile)
            for row in csv_reader:
                manager, package, snyk_vuln, ref_index, ref_name, first_url, second_urls_str = row[:7]
                try:
                    first_domain = self.extract_domain(first_url)
                    if first_domain:
                        domain_counts_by_manager[manager][first_domain] += 1
                        all_domain_counts[first_domain] += 1
                    # Parse the second_links
                    if self.flag == "2":
                        second_urls = eval(second_urls_str)
                        for link in second_urls:
                            link = link.strip()
                            if self.should_ignore(link):
                                continue
                            second_domain = self.extract_domain(link)
                            if second_domain == first_domain:
                                continue
                            if not second_domain:  # If the domain is missing, use the main_domain
                                continue
                            if second_domain == ".":
                                continue
                            domain_counts_by_manager[manager][second_domain] += 1
                            all_domain_counts[second_domain] += 1
                except:
                    pass
        output_data = []
        for domain, count in all_domain_counts.items():
            if count > 30:
                manager_counts = {manager: domain_counts_by_manager[manager].get(domain, 0)
                                  for manager in domain_counts_by_manager if
                                  domain in domain_counts_by_manager[manager]}
                output_data.append([domain, manager_counts])
        print(output_data)


        # 输出按manager分类的域名计数结果
        # for manager, domain_counts in domain_counts_by_manager.items():
        #     sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        #     print(f"Domains for manager: {manager}")
        #     for domain, count in sorted_domains:
        #         if count > 0:
        #             print(f"{domain}: {count}")
        #     print("-" * 50)
        #
        # # 输出所有URL的域名计数结果
        # sorted_all_domains = sorted(all_domain_counts.items(), key=lambda x: x[1], reverse=True)
        # print(f"Domains for all URLs:")
        # for domain, count in sorted_all_domains:
        #     if count > 0:
        #         print(f"{domain}: {count}")


if __name__ == '__main__':
    snyk_url_analysis = SnykUrlAnalysis()
    snyk_url_analysis.analyze_urls()