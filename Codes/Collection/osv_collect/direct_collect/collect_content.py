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
import requests
from selenium import webdriver
from selenium.common import TimeoutException
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup, Tag
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urljoin
from urllib.parse import urlparse


class WebPageContent:
    def __init__(self):
        current_dir = os.path.dirname(__file__)
        osv_collect_dir = os.path.dirname(current_dir)
        collection_dir = os.path.dirname(osv_collect_dir)
        codes_dir = os.path.dirname(collection_dir)
        project_dir = os.path.dirname(codes_dir)
        self.webpage_txt = os.path.join(osv_collect_dir, "article_links2.txt")
        self.collected_pagelinks = os.path.join(osv_collect_dir, "collected_article.txt")
        self.text_dir = os.path.join(project_dir, "Dataset", "Content", "osv_search")
        self.img_dir = os.path.join(project_dir, "Dataset", "Image", "osv_search")
        # self.chromedriver = os.path.join(project_dir, "utils", "chromedriver", "macarm", "chromedriver")  # blue
        self.chromedriver = os.path.join(project_dir, "utils", "chromedriver", "win32", "chromedriver.exe")  # gjj
        self.webpage_dict = {}
        self.collected_dict = {}
        self.processed_files = {}
        self.service = Service(executable_path=self.chromedriver)
        self.options = webdriver.ChromeOptions()
        self.options.add_argument("--disable-gpu")
        self.options.add_argument("--enable-javascript")

        # self.webpage_dict = {"medium_recommand": [("20240824_191625_CCCCCC", "https://zero.checkmarx.com/over-170k-users-affected-by-attack-using-fake-python-infrastructure-05a04b7e058a"), ("20240824_191625_BBBBBB", "https://zero.checkmarx.com/17-malicious-python-packages-targeting-selenium-users-to-steal-crypto-8d24628ec656")]}

    def write_text(self, content, filename):
        # 获取文件夹路径
        folder = os.path.dirname(filename)
        # 如果文件夹不存在，则创建它
        if not os.path.exists(folder):
            os.makedirs(folder)
        # 安全地写入文件，文件打开模式为 w
        with open(filename, "w", encoding="utf-8") as txtfile:
            txtfile.write(content)
            txtfile.flush()

    def write_collected_pagelinks(self, timestamp, web, postdate, url):
        # 获取文件夹路径
        folder = os.path.dirname(self.collected_pagelinks)
        # 如果文件夹不存在，则创建它
        if not os.path.exists(folder):
            os.makedirs(folder)
        # 现在可以安全地写入文件
        with open(self.collected_pagelinks, "a", encoding="utf-8") as txtfile:
            txtfile.write(timestamp + '\t' + web + '\t' + postdate + '\t' + url + '\n')
            txtfile.flush()

    # 从self.webpage_txt中读取数据，并将数据解析后存储到self.webpage_dict字典中
    def read_txt(self):
        with open(self.webpage_txt) as txtfile:
            urlslist = txtfile.readlines()
            for url in urlslist:
                url_split = url.split("\t")
                timestamp = url_split[0].strip()
                source = url_split[1].strip()
                package_manager = url_split[2].strip()
                package_name = url_split[3].strip()
                postdate = url_split[4].strip()
                page_url = url_split[5].strip()
                if source in self.webpage_dict:
                    self.webpage_dict[source].append((timestamp, postdate, page_url))
                else:
                    self.webpage_dict[source] = [(timestamp, postdate, page_url)]

    def find_processed_files(self):
        with open(self.collected_pagelinks) as txtfile:
            urlslist = txtfile.readlines()
            for url in urlslist:
                url_split = url.split("\t")
                timestamp = url_split[0].strip()
                source = url_split[1].strip()
                if source in self.processed_files:
                    self.processed_files[source].append(timestamp)
                else:
                    self.processed_files[source] = [timestamp]

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
            if table:
                for tr in table[0].find_all('tr'):
                    # Extract each row's cells and join with '\t'
                    row = '\t'.join(td.get_text().strip() for td in tr.find_all('td'))
                    table_data += row + '\n'
        except:
            pass
        return table_data

    # 下载图片
    def save_image_from_url(self, img_url, save_dir, save_path):
        try:
            response = requests.get(img_url, stream=True)  # 发起GET请求获取图片内容
            if response.status_code == 200:  # 请求成功
                os.makedirs(save_dir, exist_ok=True)
                with open(save_path, 'wb') as f:  # 将图片内容写入指定的保存路径
                    f.write(response.content)
                return True
            else:  # 下载失败
                print(f"Failed to download image from {img_url}")
                return False
        except Exception as e:  # 异常
            print(f"Exception occurred while downloading image: {str(e)}")
            return False

    def format_filename(self, img_url, web_name, timestamp):
        # 解析url
        parsed_url = urlparse(img_url)
        img_path = parsed_url.path  # 获取路径部分

        img_filename = os.path.basename(img_path)  # 获取文件名部分
        # 定义不允许的特殊字符集合，只允许字母、数字、下划线、空格和点号
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.")
        # 使用re模块的sub函数，将不允许的字符替换为空字符串
        img_filename = re.sub(f"[^{allowed_chars}]", "", img_filename)

        img_save_dir = os.path.join(self.img_dir, web_name, timestamp)
        img_save_path = os.path.join(img_save_dir, img_filename)  # 保存到 dataset 的文件夹中

        return img_filename, img_save_dir, img_save_path

    # 解析传入的网页元素element中的各种标签，并将其内容处理成文本形式返回
    def parse_elements(self, driver, element, web_name, timestamp):
        # 找到图片对应的外层标签
        def find_outer_tag(outermost_tag, current_tag):
            while id(current_tag.parent) != id(outermost_tag):
                current_tag = current_tag.parent
            return current_tag

        page_content = ""  # Stores the content of the page
        processed_tags = set()  # To keep track of processed tags
        images = set()
        img_data = dict()

        # Use recursive traversal of the BeautifulSoup tag tree
        def process_tag(tag):
            nonlocal page_content
            tag_id = id(tag)
            if tag_id in processed_tags:
                return
            processed_tags.add(tag_id)

            # Replace <br> tags with newlines
            for br in tag.find_all("br"):
                br.replace_with("\n")

            # Handle images
            for img_tag in tag.find_all(src=True):
                src = img_tag['src']
                base_url = driver.current_url
                img_url = urljoin(base_url, src)
                if img_url.lower().endswith(('.png', '.jpg', '.jpeg')):
                    if img_url not in images:
                        img_filename, img_save_dir, img_save_path = self.format_filename(img_url, web_name,
                                                                                         timestamp)
                        images.add(img_url)
                        if self.save_image_from_url(img_url, img_save_dir, img_save_path):
                            # page_content += '\nimage: ' + img_save_path
                            outer_tag = find_outer_tag(tag, img_tag)
                            img_id = id(outer_tag)
                            img_data[img_id] = img_save_path
                        else:
                            print(f"Failed to save image from {img_url}")
            if id(tag) in img_data:
                page_content += '\n' + 'image: ' + img_data[id(tag)]

            # Handle paragraphs, code blocks, headings
            if tag.name in ['p', 'code', 'h1', 'h2', 'h3']:
                tag_content = tag.get_text().strip()
                page_content += '\n' + tag_content

            # Handle tables
            elif tag.name == 'table':
                table_content = self.parsetable(tag)
                page_content += '\n' + table_content

            # Handle lists
            elif tag.name in ['ul', 'ol']:
                list_content = self.parse_list_tags(tag)
                page_content += '\n' + list_content

            # Handle iframes
            elif tag.name == 'iframe':
                time.sleep(5)  # Wait for iframe content to load
                if tag.get('src'):
                    iframe_src = tag.get('src')
                    iframe_content = self.process_iframe(iframe_src)
                    page_content += '\n' + iframe_content
                    with open("iframe.txt", "a") as txtfile:
                        txtfile.write(iframe_content)
                        txtfile.write("\n")

            # Process all other tags recursively
            else:
                for child in tag.children:
                    if isinstance(child, Tag):  # Ensure child is a tag
                        process_tag(child)

        # Get all elements, including nested ones
        element_html = element.get_attribute('outerHTML')
        soup = BeautifulSoup(element_html, 'html.parser')

        # Check if the element contains any of the specified tags
        if soup.find('p'):
            # Process all tags recursively
            for tag in soup.find_all(recursive=True):
                process_tag(tag)
        else:
            # If no specified tags are found, extract the text directly
            page_content = soup.get_text().strip()

        return page_content

    def print_all_child_tags(self, element):
        # 首先打印当前元素的标签名
        print(element.tag_name)
        # 递归遍历所有子元素
        children = element.find_elements(By.XPATH, "./*")
        for child in children:
            self.print_all_child_tags(child)

    def medium_recommand_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'medium_recommand'
        for timestamp, postdate, page_url in self.webpage_dict["medium_recommand"]:
            try:
                if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                    print("medium_recommand processed: ", timestamp)
                    continue
                filename = timestamp + ".txt"
                print('medium_recommand', timestamp, page_url)
                count += 1
                driver.get(page_url)
                # 定义JavaScript脚本实现平滑滚动
                smooth_scroll_script = """
                let intervalId = setInterval(function() {
                    window.scrollBy(0, 200); // 每次向下滚动50像素
                }, 100); // 每100毫秒滚动一次

                // 设置一个超时，以防无限滚动
                setTimeout(function() {
                    clearInterval(intervalId);
                }, 15000); // 10秒后停止滚动
                """
                # 执行JavaScript脚本
                driver.execute_script(smooth_scroll_script)
                # driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(20)
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".du.bh.iz.ja.jb.jc")))
                content_div = driver.find_elements(By.CSS_SELECTOR, ".du.bh.iz.ja.jb.jc")[1]
                # content_div = driver.find_element(By.CSS_SELECTOR, ".du.bh.iz.ja.jb.jc")
                # WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".ci.bh.fz.ga.gb.gc")))
                # content_div = driver.find_elements(By.CSS_SELECTOR, ".ci.bh.fz.ga.gb.gc")[1]
                # self.print_all_child_tags(content_div)
                page_content = self.parse_elements(driver, content_div, web_name, timestamp)
                print(page_content)
                self.write_text(page_content, os.path.join(os.path.join(self.text_dir, "medium_recommand"), filename))
                self.write_collected_pagelinks(timestamp, 'medium_recommand', postdate, page_url)
            except:
                print('medium_recommand', page_url, "------Error-------")

    def sonatype_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)

        web_name = 'sonatype'
        for timestamp, postdate, page_url in self.webpage_dict["sonatype"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("sonatype processed:", timestamp)
                continue

            try:
                print("sonatype", page_url)
                driver.get(page_url)
                time.sleep(3)  # 等待页面加载
                filename = timestamp + ".txt"
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "hs_cos_wrapper_post_body")))
                post_content = driver.find_element(By.ID, "hs_cos_wrapper_post_body")
                webpage_content = self.parse_elements(driver, post_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "sonatype"), filename))
                self.write_collected_pagelinks(timestamp, 'sonatype', postdate, page_url)
            except:
                print('sonatype', page_url, "------Error-------")

    def thehackernews_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)

        web_name = 'thehackernews'
        for timestamp, postdate, page_url in self.webpage_dict["thehackernews"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("thehackernews processed:", timestamp)
                continue

            try:
                print("thehackernews", page_url)
                driver.get(page_url)
                time.sleep(5)  # 等待页面加载
                filename = timestamp + ".txt"
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "articlebody")))
                post_content = driver.find_element(By.ID, "articlebody")
                webpage_content = self.parse_elements(driver, post_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "thehackernews"), filename))
                self.write_collected_pagelinks(timestamp, 'thehackernews', postdate, page_url)
            except:
                print('thehackernews', page_url, "------Error-------")

    def bleepingcomputer_content(self):
        web_name = 'bleepingcomputer'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for timestamp, postdate, page_url in self.webpage_dict["bleepingcomputer"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("bleepingcomputer processed:", timestamp)
                continue

            try:
                print('bleepingcomputer', page_url)
                driver.get(page_url)
                time.sleep(10)
                filename = timestamp + ".txt"

                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "articleBody")))
                # driver.execute_script("window.stop();")  # 立即停止加载其余部分

                article_section = driver.find_element(By.CLASS_NAME, "articleBody")
                webpage_content = self.parse_elements(driver, article_section, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content,
                                os.path.join(os.path.join(self.text_dir, "bleepingcomputer"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print('bleepingcomputer', page_url, "------Error-------")

    def checkmarx_content(self):
        # 启动chrome浏览器
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'checkmarx'
        # 遍历self.webpage_dict["checkmarx"]中的每个元素，元素为(timestamp, page_url)的元组
        for timestamp, postdate, page_url in self.webpage_dict["checkmarx"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("checkmarx processed:", timestamp)
                continue

            count += 1
            driver.get(page_url)  # 使用driver打开page_url对应的网页
            time.sleep(3)  # 等待3秒，确保页面加载完成

            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("checkmarx processed: ", timestamp)
                continue
            filename = timestamp + ".txt"  # 构造文件名，由timestamp和.txt组成

            print('checkmarx', timestamp, page_url)
            # 滚动浏览器窗口至页面底部
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            try:
                # WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".elementor-element.elementor-element-2bd10d61.elementor-widget.elementor-widget-theme-post-content")))
                # article_content = driver.find_element(By.CSS_SELECTOR, ".elementor-element.elementor-element-2bd10d61.elementor-widget.elementor-widget-theme-post-content")

                # 等待10秒直到找到<article>
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "article")))
                # 找到 <article> 标签的元素
                article_content = driver.find_element(By.TAG_NAME, "article")

                # 调用self.parse_elements方法解析页面内容
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "checkmarx"), filename))
                self.write_collected_pagelinks(timestamp, 'checkmarx', postdate, page_url)
            except:
                print('checkmarx', page_url, "------Error-------")

    def datadoghq_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'datadoghq'
        for timestamp, postdate, page_url in self.webpage_dict["datadoghq"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("datadoghq processed:", timestamp)
                continue

            try:
                count += 1
                driver.get(page_url)
                time.sleep(3)
                filename = timestamp + ".txt"
                print('datadoghq', 'timestamp:', timestamp, 'page_url:', page_url)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, ".article-content.relative")))
                article_content = driver.find_element(By.CSS_SELECTOR, ".article-content.relative")
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "datadoghq"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print('datadoghq', page_url, "------Error-------")

    def socket_content(self):
        web_name = 'socket'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["socket"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("socket processed:", timestamp)
                continue

            try:
                print('socket', 'timestamp:', timestamp, 'page_url:', page_url)
                filename = timestamp + ".txt"

                count += 1
                driver.get(page_url)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".prose.css-0")))
                article_content = driver.find_element(By.CSS_SELECTOR, ".prose.css-0")
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                # self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "socket"), "socket_" + str(count) + ".txt"))
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "socket"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print('socket', page_url, "------Error-------")

    def reversinglabs_content(self):
        web_name = 'reversinglabs'
        # self.find_processed_files(os.path.join(self.text_dir, "reversinglabs"))
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["reversinglabs"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("reversinglabs processed: ", timestamp)
                continue

            filename = timestamp + ".txt"
            try:
                print('reversinglabs', timestamp, page_url)
                count += 1
                driver.get(page_url)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "hs_cos_wrapper_post_body")))
                article_content = driver.find_element(By.ID, "hs_cos_wrapper_post_body")
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "reversinglabs"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print('reversinglabs', page_url, "------Error-------")

    def fortinet_content(self):
        web_name = 'fortinet'
        # self.find_processed_files(os.path.join(self.text_dir, "fortinet"))
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["fortinet"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("fortinet processed: ", timestamp)
                continue

            filename = timestamp + ".txt"
            try:
                print('fortinet', timestamp, page_url)
                count += 1
                driver.get(page_url)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, ".aem-Grid.aem-Grid--12.aem-Grid--default--12")))
                article_content = driver.find_element(By.CSS_SELECTOR, ".aem-Grid.aem-Grid--12.aem-Grid--default--12")
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "fortinet"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print('fortinet', page_url, "------Error-------")

    def phylum_content(self):
        web_name = 'phylum'
        # self.find_processed_files(os.path.join(self.text_dir, "phylum"))
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["phylum"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("phylum processed: ", timestamp)
                continue

            filename = timestamp + ".txt"

            try:
                print('phylum', timestamp, page_url)
                count += 1
                driver.get(page_url)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".gh-content.gh-canvas")))
                article_content = driver.find_element(By.CSS_SELECTOR, ".gh-content.gh-canvas")
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "phylum"), filename))
                self.write_collected_pagelinks(timestamp, 'phylum', postdate, page_url)
            except:
                print('phylum', page_url, "------Error-------")


if __name__ == '__main__':
    webpage_content = WebPageContent()
    webpage_content.read_txt()
    webpage_content.find_processed_files()

    # webpage_content.aabbcc_content()
    webpage_content.reversinglabs_content()
    webpage_content.medium_recommand_content()
    webpage_content.checkmarx_content()
    webpage_content.phylum_content()
    webpage_content.thehackernews_content()
    webpage_content.sonatype_content()
    webpage_content.bleepingcomputer_content()
    webpage_content.fortinet_content()
    webpage_content.datadoghq_content()
    webpage_content.socket_content()
