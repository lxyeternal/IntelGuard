# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : webpage_content.py
# @Project  : PMonitor
# Time      : 25/1/24 9:58 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import csv
import re
import time
import praw
import subprocess
from datetime import datetime
# from readability import Document
import requests
from selenium import webdriver
from Configs.config import HEADER
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup, Tag
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
from urllib.parse import urljoin
from urllib.parse import urlparse, unquote


class WebPageContent:
    def __init__(self):
        self.text_dir = "../../Dataset/Case/"
        self.chromedriver = '../../utils/chromedriver/win32/chromedriver.exe'
        self.service = Service(executable_path=self.chromedriver)
        self.options = webdriver.ChromeOptions()
        self.options.add_argument("--disable-gpu")
        self.options.add_argument("--enable-javascript")

    def write_text(self, content, filename):
        with open(filename, "a", encoding="utf-8") as txtfile:
            txtfile.write(content)

    def parsetable(self, table_element):
        # 提取表头
        table_content = ""
        header_row = table_element.find('tr')
        headers = [th.text.strip() for th in header_row.find_all('th')]
        table_content = table_content + '\n' + '\t'.join(headers)
        # 提取表格的每一行
        for tr in table_element.find_all('tr')[1:]:  # 跳过表头行
            row = [td.text.strip() for td in tr.find_all('td')]
            table_content = table_content + '\n' + '\t'.join(row)
        return table_content

    def parse_list_tags(self, list_tag):
        list_content = ""
        for li in list_tag.find_all('li', recursive=False):
            # 对于每个li元素，提取其中的文本
            # 如果li元素包含ul或ol，递归调用parse_list_tags
            li_content = li.get_text().strip()
            nested_lists = li.find_all(['ul', 'ol'], recursive=False)
            for nested_list in nested_lists:
                li_content += '\n' + self.parse_list_tags(nested_list)
            list_content += '\n' + li_content
        return list_content

    def parsecodes(self, page_element):
        codes = ""
        for code in page_element.find_all('code'):
            codes = codes + '\n' + code.text.strip()
        return codes

    def extract_body(self, doc):
        page_content = ""
        if doc.summary().startswith("<html>"):
            soup = BeautifulSoup(doc.summary(), "html.parser")
            for tag in soup.find_all(recursive=False):  # True 使得 find_all 返回所有标签
                if tag.name == "table":
                    table_content = self.parsetable(tag)
                    page_content = page_content + '\n' + table_content
                else:
                    page_content = page_content + '\n' + tag.text.strip()
        else:
            page_content = doc.summary()
        return page_content

    def process_iframe(self, medium_iframe_src):
        print(medium_iframe_src)
        table_data = ""
        try:
            driver_iframe = webdriver.Chrome(service=self.service, options=self.options)
            driver_iframe.implicitly_wait(5)
            driver_iframe.get(medium_iframe_src)
            time.sleep(2)
            html = driver_iframe.page_source
            soup = BeautifulSoup(html, 'html.parser')
            table = soup.find_all('table')
            for tr in table[0].find_all('tr'):
                # 提取每行的单元格并用'\t'拼接
                row = '\t'.join(td.get_text().strip() for td in tr.find_all('td'))
                table_data += row + '\n'
        except:
            pass
        return table_data

    # 解析传入的网页元素 element 中的各种标签，并将其内容处理成文本形式返回
    def parse_elements(self, driver, element, web_name, timestamp):
        page_content = ""  # 存储页面内容的字符串
        processed_tags = set()  # 用于跟踪已处理的标签

        def process_tag(tag):
            nonlocal page_content
            if tag in processed_tags:
                return
            processed_tags.add(tag)
            # 替换 <br> 标签为换行符
            for br in tag.find_all("br"):
                br.replace_with("\n")
            # 对特定标签应用特定处理函数
            # 段落、代码块、标题
            if tag.name in ['p', 'code', 'h1', 'h2', 'h3']:
                tag_content = tag.get_text().strip()
                page_content += '\n' + tag_content
                return
            # 表格
            elif tag.name == 'table':
                table_content = self.parsetable(tag)
                page_content += '\n' + table_content
                return
            # 无序列表和有序列表
            elif tag.name in ['ul', 'ol']:
                list_content = self.parse_list_tags(tag)
                page_content += '\n' + list_content
                return
            # iframe
            elif tag.name == 'iframe':
                if tag.get('src'):
                    iframe_src = tag.get('src')
                    iframe_content = self.process_iframe(iframe_src)
                    page_content += '\n' + iframe_content
                    with open("iframe.txt", "a") as txtfile:
                        txtfile.write(iframe_content)
                        txtfile.write("\n")
                return
            # 处理其他标签，遍历其子标签
            else:
                # 如果标签不是特定的标签，则遍历其子标签
                if tag.children:
                    for child in tag.children:
                        if isinstance(child, Tag):  # 确保子元素是一个标签
                            process_tag(child)
                else:
                    # 如果标签没有子标签，则直接提取其文本
                    tag_content = tag.get_text().strip()
                    page_content += '\n' + tag_content

        children = element.find_elements(By.XPATH, "./*")  # 获取元素的所有子元素
        for child in children:
            # 如果子元素是 iframe 标签，处理 iframe 内容
            if child.tag_name.lower() == "iframe":
                iframe_src = child.get_attribute('src')
                iframe_content = self.process_iframe(iframe_src)
                page_content += iframe_content
                with open("iframe.txt", "a") as txtfile:
                    txtfile.write(iframe_content)
                    txtfile.write("\n")
            # 如果子元素不是 iframe 标签，获取其 outerHTML，并用 BeautifulSoup 解析
            else:
                child_html = child.get_attribute('outerHTML')
                child_soup = BeautifulSoup(child_html, 'html.parser')
                # 仅处理顶层标签
                for tag in child_soup.children:
                    if tag.name:  # 确保是 BeautifulSoup 标签
                        process_tag(tag)
        return page_content

    def print_all_child_tags(self, element):
        # 首先打印当前元素的标签名
        print(element.tag_name)
        # 递归遍历所有子元素
        children = element.find_elements(By.XPATH, "./*")
        for child in children:
            self.print_all_child_tags(child)

    def thehackernews_case_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        timestamp = "thehackernews_case"
        page_url = "https://thehackernews.com/2022/08/pypi-repository-warns-python-project.html"
        filename = timestamp + ".txt"
        print(timestamp, page_url)
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        web_name = 'thehackernews'

        driver.get(page_url)
        time.sleep(3)
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "articlebody")))
            post_content = driver.find_element(By.CLASS_NAME, "articlebody")
            # 递归遍历 articlebody 中的所有标签
            webpage_content = self.parse_elements(driver, post_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(self.text_dir, filename))
        except:
            pass
            print("thehackernews case error")

    def secrss_case_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        timestamp = "secrss_case"
        page_url = "https://www.secrss.com/articles/45927"
        filename = timestamp + ".txt"
        print(timestamp, page_url)
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        web_name = 'secrss'

        driver.get(page_url)
        time.sleep(3)
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "article")))
            post_content = driver.find_element(By.CLASS_NAME, "article")
            # 递归遍历 articlebody 中的所有标签
            webpage_content = self.parse_elements(driver, post_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(self.text_dir, filename))
        except:
            pass
            print("secrss case error")

    def checkmarx_case_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        timestamp = "checkmarx_case"
        page_url = "https://checkmarx.com/blog/malicious-pypi-user-strikes-again-with-typosquatting-starjacking-and-unpacks-tailor-made-malware-written-in-c/"
        filename = timestamp + ".txt"
        print(timestamp, page_url)
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        web_name = 'checkmarx'

        driver.get(page_url)  # 使用driver打开page_url对应的网页
        time.sleep(3)  # 等待3秒，确保页面加载完成
        # 滚动浏览器窗口至页面底部
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            # 等待10秒直到找到<article>
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "article")))
            # 找到 <article> 标签的元素
            article_content = driver.find_element(By.TAG_NAME, "article")

            # 调用self.parse_elements方法解析页面内容
            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(self.text_dir, filename))
        except:
            pass
            print("checkmarx case error")

if __name__ == '__main__':
    webpage_content = WebPageContent()
    webpage_content.thehackernews_case_content()
    webpage_content.secrss_case_content()
    # webpage_content.checkmarx_case_content()
