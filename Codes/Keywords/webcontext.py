# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : webcontext.py
# @Project  : PMonitor
# Time      : 2023/12/3 14:36
# Author    : honywen
# version   : python 3.8
# Description：
"""



# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : link_search.py
# @Project  : PMonitor
# Time      : 2023/10/19 22:31
# Author    : honywen
# version   : python 3.8
# Description：
"""


import csv
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from urllib.parse import urlparse
from Configs.config import HEADER
from multiprocessing import Pool, Manager
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support import expected_conditions as EC


class SnykBacktrace:
    def __init__(self) -> None:
        self.snyk_malicious_csv = "../csv/{}_snyk_malicious.csv"
        self.chromedriver = '../utils/chromedriver/macarm/chromedriver'
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(service=service, options=options)
        self.contentdriver = webdriver.Chrome(service=service, options=options)


    def save_txt(self, text_content, file_path):
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(text_content)

    def read_snyk_csv(self):
        all_snyk_link = list()
        for manager in ["pypi", "npm"]:
            snyk_info_csv = self.snyk_malicious_csv.format(manager)
            with open(snyk_info_csv, encoding="utf-8-sig") as csvfile:
                csv_reader = csv.reader(csvfile)  # 使用csv.reader读取csvfile中的文件
                for idx, row in enumerate(csv_reader):
                    if idx != 0:
                        pkgname = row[0]
                        snyk_link = row[1]
                        all_snyk_link.append([manager, pkgname, snyk_link])
        return all_snyk_link

    def bulit_header(self, url):
        parsed_url = urlparse(url)
        # 获取域名
        referer = "{}://{}".format(parsed_url.scheme, parsed_url.netloc)
        HEADER["Referer"] = referer

    def content_links_selenium(self, url):
        try:
            self.contentdriver.set_page_load_timeout(30)
            self.contentdriver.get(url)
            # 等待页面加载
            WebDriverWait(self.contentdriver, 30).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            # 获取页面的文本内容
            page_text = self.contentdriver.find_element(By.TAG_NAME, "body").text
            return page_text
        except TimeoutException:
            print("Timed out waiting for page to load")
            return ""

    def content_links_requests(self, url):
        self.bulit_header(url)
        headers = HEADER
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            # 获取网页的全部文本内容
            page_text = soup.get_text(separator=' ', strip=True)
            return page_text
        except requests.RequestException as e:
            print(f"Error fetching the page: {e}")
            return ""

    def extract_snyk_reflink(self, manager, pkgname, snyk_link):
        self.driver.get(snyk_link)
        self.driver.implicitly_wait(10)
        container = self.driver.find_element(By.CSS_SELECTOR, ".vue--layout-container.vuln-page__body-wrapper.grid-wrapper")
        left = container.find_element(By.CLASS_NAME, "left")
        try:
            markdown_section = left.find_elements(By.CLASS_NAME, "markdown-section")[2]
            markdown_description = markdown_section.find_element(By.CLASS_NAME, "vue--prose")
            # 使用XPath定位具有类“vue--heading heading”的<h2>标签并且文本内容为"References"
            links = markdown_description.find_elements(By.XPATH, ".//ul/li/a")
            for idx, link in enumerate(links):
                url = link.get_attribute("href")
                ref_content = self.content_links_requests(url)
                if ref_content == "":
                    ref_content = self.content_links_selenium(url)
                file_path = f"text/{manager}_{pkgname}_{idx}.txt"
                self.save_txt(ref_content, file_path)
        except:
            pass


def snykworker(links_subset, shared_results):
    snykbacktrace = SnykBacktrace()
    for link in links_subset:
        try:
            snykbacktrace.extract_snyk_reflink(link[0], link[1], link[2])
            shared_results.append(link[1])  # 假设我们想记录处理过的链接
            print(f"Processed: {link[1]}")
        except:
            pass


def snykmain():
    snykbacktrace = SnykBacktrace()
    all_snyk_link = snykbacktrace.read_snyk_csv()
    # 需要处理的链接列表
    searched_unique_lst = []
    to_process_links = [link for link in all_snyk_link if link[1] not in searched_unique_lst]
    # 划分数据
    num_processes = 10
    chunk_size = len(to_process_links) // num_processes
    chunks = [to_process_links[i:i + chunk_size] for i in range(0, len(to_process_links), chunk_size)]
    with Manager() as manager:
        shared_results = manager.list()  # 用于存储处理结果的列表
        with Pool(num_processes) as p:  # 使用指定数量的进程
            p.starmap(snykworker, [(chunk, shared_results) for chunk in chunks])
        # 打印处理结果
        for result in shared_results:
            print(result)


if __name__ == '__main__':

    snykmain()
