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
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.webpage_txt = os.path.join(current_dir, "pagelinks", "waiting_collection.txt")
        self.collected_pagelinks = os.path.join(current_dir, "pagelinks", "collected_pagelinks.txt")
        self.text_dir = os.path.join(project_dir, "Dataset", "Content")
        self.img_dir = os.path.join(project_dir, "Dataset", "Image")
        # self.chromedriver = os.path.join(project_dir, "utils", "chromedriver", "macarm", "chromedriver")  # blue
        self.chromedriver = os.path.join(project_dir, "utils", "chromedriver", "win32", "chromedriver.exe")  # gjx
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
                postdate = url_split[2].strip()
                page_url = url_split[3].strip()
                if source in self.webpage_dict:
                    self.webpage_dict[source].append((timestamp, postdate, page_url))
                else:
                    self.webpage_dict[source] = [(timestamp, postdate, page_url)]

    def write_csv(self, data):
        with open("../Analysis/github_maldata.csv", "a") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(data)
            # write data to the csv file right now
            csvfile.flush()

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

    def scroll_to_bottom(self, driver):
        # 初始化滚动前的高度
        initial_scroll_height = driver.execute_script("return document.body.scrollHeight")
        while True:
            # 每次滚动一小部分
            driver.execute_script("window.scrollBy(0, 300);")
            # 等待页面加载新内容（如果有的话）
            time.sleep(0.5)
            # 检查是否到达了页面底部
            new_scroll_height = driver.execute_script("return document.body.scrollHeight")
            if new_scroll_height == initial_scroll_height:
                break
            initial_scroll_height = new_scroll_height

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

        # Process all tags recursively
        for tag in soup.find_all(recursive=True):
            process_tag(tag)

        return page_content

    def print_all_child_tags(self, element):
        # 首先打印当前元素的标签名
        print(element.tag_name)
        # 递归遍历所有子元素
        children = element.find_elements(By.XPATH, "./*")
        for child in children:
            self.print_all_child_tags(child)

    def aabbcc_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        timestamp = "checkmarx1"
        # page_url = "https://snyk.io/blog/securing-artifactory-using-snyk/"
        page_url = "https://www.sonatype.com/blog/npm-packages-caught-exfiltrating-kubernetes-config-ssh-keys"
        print(timestamp, page_url)
        web_name = 'checkmarx'
        driver.get(page_url)
        time.sleep(3)
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "hs_cos_wrapper_post_body")))  # 等待页面元素加载
        article_content = driver.find_element(By.ID, "hs_cos_wrapper_post_body")  # 定位文章内容元素
        page_content = self.parse_elements(driver, article_content, web_name, timestamp)
        print(page_content)

    def medium_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'medium'
        for timestamp, postdate, page_url in self.webpage_dict["medium"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("medium processed:", timestamp)
                continue
            print(page_url)
            try:
                filename = timestamp + ".txt"
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

                try:
                    WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, ".ch.bg.ga.gb.gc.gd")))
                    content_div = driver.find_elements(By.CSS_SELECTOR, ".ch.bg.ga.gb.gc.gd")[1]
                except:
                    WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, ".ci.bh.fz.ga.gb.gc")))
                    content_div = driver.find_elements(By.CSS_SELECTOR, ".ci.bh.fz.ga.gb.gc")[1]
                # self.print_all_child_tags(content_div)
                page_content = self.parse_elements(driver, content_div, web_name, timestamp)
                print(page_content)
                self.write_text(page_content, os.path.join(os.path.join(self.text_dir, "medium"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print("------Error-------")

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
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".ci.bh.fz.ga.gb.gc")))
                content_div = driver.find_elements(By.CSS_SELECTOR, ".ci.bh.fz.ga.gb.gc")[1]
                # self.print_all_child_tags(content_div)
                page_content = self.parse_elements(driver, content_div, web_name, timestamp)
                print(page_content)
                self.write_text(page_content, os.path.join(os.path.join(self.text_dir, "medium_recommand"), filename))
                self.write_collected_pagelinks(timestamp, 'medium_recommand', postdate, page_url)
            except:
                print(page_url, "------Error-------")

    def qianxin_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)

        web_name = 'qianxin'
        for timestamp, postdate, page_url in self.webpage_dict["qianxin"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("qianxin processed:", timestamp)
                continue

            try:
                driver.get(page_url)
                if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                    print("qianxin processed: ", timestamp)
                    continue
                filename = timestamp + ".txt"
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "post-content")))
                post_content = driver.find_element(By.CLASS_NAME, "post-content")
                #  递归遍历article_content中的所有标签，直到没有子标签为止，如果子标签是p标签，code标签，h1标签，h2标签，h3标签，则输出标签的内容，如果是table标签的话，就需要单独处理，还原出表格的内容和格式，但是需要注意的是当解析了标签的内容之后，就需要跳过这个标签，以防止输出重复
                webpage_content = self.parse_elements(driver, post_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(self.text_dir, filename))
                self.write_collected_pagelinks(timestamp, 'qianxin', postdate, page_url)
            except:
                pass

    def snyk_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'snyk'
        for timestamp, postdate, page_url in self.webpage_dict["snyk"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("snyk processed:", timestamp)
                continue

            print(page_url)
            count += 1
            driver.get(page_url)
            time.sleep(3)
            filename = timestamp + ".txt"
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "txt-rich-long")))
            article_content = driver.find_element(By.CLASS_NAME, "txt-rich-long")
            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "snyk"), filename))
            self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

    def github_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        page_count = len(self.webpage_dict["github"])
        for timestamp, page_url in self.webpage_dict["github"]:
            print(str(page_count) + "   " + page_url)
            driver.get(page_url)
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "main")))
            article_main = driver.find_element(By.TAG_NAME, "main")
            Subhead_description = article_main.find_element(By.CLASS_NAME, "Subhead-description")
            v_align_middle = Subhead_description.find_element(By.CLASS_NAME, "v-align-middle").text.strip()
            datatime = Subhead_description.find_element(By.TAG_NAME, "relative-time").get_attribute("datetime")
            table_content = article_main.find_element(By.CSS_SELECTOR, ".gutter-lg.gutter-condensed.clearfix")
            name_manager = table_content.find_element(By.CSS_SELECTOR, ".float-left.col-12.col-md-6.pr-md-2")
            package_name = name_manager.find_element(By.CSS_SELECTOR, ".f4.color-fg-default.text-bold").text.strip()
            manager_name = name_manager.find_element(By.CSS_SELECTOR, ".color-fg-muted.f4.d-inline-flex").text
            manager_name = manager_name.replace("(", "").replace(")", "").strip()
            version_div = table_content.find_element(By.CSS_SELECTOR, ".float-left.col-6.col-md-3.py-2.py-md-0.pr-2")
            version = version_div.find_element(By.CSS_SELECTOR, ".f4.color-fg-default").text.strip()
            description_div = table_content.find_element(By.CSS_SELECTOR, ".Box-body.px-5.pb-5")
            description = description_div.text
            right_table = article_main.find_element(By.CSS_SELECTOR, ".col-12.col-md-3.float-left.pt-3.pt-md-0")
            weakness = right_table.find_element(By.CSS_SELECTOR,
                                                ".discussion-sidebar-item.js-repository-advisory-details").text.strip()
            print(v_align_middle, datatime, package_name, manager_name, version, weakness)
            self.write_csv([v_align_middle, datatime, package_name, manager_name, version, description, weakness])
        driver.quit()

    def bleepingcomputer_content(self):
        web_name = 'bleepingcomputer'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for timestamp, postdate, page_url in self.webpage_dict["bleepingcomputer_pypi"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("bleepingcomputer processed:", timestamp)
                continue

            print(page_url)
            driver.get(page_url)
            time.sleep(10)
            filename = timestamp + ".txt"
            try:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "article-section")))
                # driver.execute_script("window.stop();")  # 立即停止加载其余部分
            except:
                article_section = driver.find_element(By.CLASS_NAME, "article-section")
                webpage_content = self.parse_elements(driver, article_section, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content,
                                os.path.join(os.path.join(self.text_dir, "bleepingcomputer_pypi"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

    def jfrog_content(self):
        web_name = 'jfrog'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["jfrog"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("jfrog processed:", timestamp)
                continue

            print(page_url)
            count += 1
            driver.get(page_url)
            time.sleep(5)
            filename = timestamp + ".txt"
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            article_section = driver.find_element(By.CLASS_NAME, "entry-content")
            webpage_content = self.parse_elements(driver, article_section, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "jfrog"), filename))
            self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

    def sonatype_oss_content(self):
        web_name = 'sonatype_oss'  # 定义网站名称变量
        # self.find_processed_files(os.path.join(self.text_dir, "sonatype_oss"))  # 查找 'sonatype_oss' 目录下已处理的文件
        driver = webdriver.Chrome(service=self.service, options=self.options)  # 初始化Chrome浏览器驱动
        driver.implicitly_wait(5)  # 设置隐式等待时间
        count = 0  # 初始化页面计数器
        for timestamp, postdate, page_url in self.webpage_dict["sonatype_oss"]:  # 遍历页面URL和时间戳
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("sonatype_oss processed:", timestamp)
                continue

            count += 1  # 增加页面计数
            driver.get(page_url)  # 加载页面URL
            time.sleep(3)  # 等待页面加载
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("sonatype_oss processed: ", timestamp)
                continue
            filename = timestamp + ".txt"  # 根据时间戳创建文件名
            print("sonatype_oss", timestamp, page_url)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")  # 滚动到页面底部

            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "hs_cos_wrapper_post_body")))  # 等待页面元素加载
            article_content = driver.find_element(By.ID, "hs_cos_wrapper_post_body")  # 定位文章内容元素

            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)  # 解析页面内容
            print(webpage_content)  # 打印页面内容
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "sonatype_oss"), filename))  # 写入内容到文件
            self.write_collected_pagelinks(timestamp, 'sonatype_oss', postdate, page_url)

    def checkmarx_content(self):
        # 启动chrome浏览器
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'checkmarx'
        # 遍历self.webpage_dict["checkmarx"]中的每个元素，元素为(timestamp, page_url)的元组
        for timestamp, postdate, page_url in self.webpage_dict["checkmarx"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("qianxin processed:", timestamp)
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
                pass
                print("Error")

    def datadoghq_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        web_name = 'datadoghq'
        for timestamp, postdate, page_url in self.webpage_dict["datadoghq"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("datadoghq processed:", timestamp)
                continue

            count += 1
            driver.get(page_url)
            time.sleep(3)
            filename = timestamp + ".txt"
            print('timestamp:', timestamp, 'page_url:', page_url)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".article-content.relative")))
            article_content = driver.find_element(By.CSS_SELECTOR, ".article-content.relative")
            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
            # print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "datadoghq"), filename))
            self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

    def socket_content(self):
        web_name = 'socket'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["socket"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("socket processed:", timestamp)
                continue

            print('timestamp:', timestamp, 'page_url:', page_url)
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

    def twitter_content(self):
        usernames = ["@securestep9", "@garthoid", "@nicksdavis", "@bzvr_", "@PabloMxNL", "@R_Hubby", "@checkmarxoss",
                     "@dineshdina04", "@ZishaTwersky", "@idanplotnik", "@pypi", "@piergiorgiolad", "@TheHackersNews",
                     "@Phylum_IO", "@fe7ch", "@blackorbird", "@Find_My_Threat", "@ThePyPA", "@jossefharush",
                     "@loginsoft_inc", "@daffainfo", "@cosmin_ilie", "@jensengelke", "@Timothy_Gu", "@MaKolarik",
                     "@mylinkingcom", "@drubicza", "@splushi", "@jamellon123", "@machycek"]
        usernames = ["@machycek"]
        # 循环遍历用户名列表
        for username in usernames:
            # 构建命令
            command = ['python',
                       '/Users/blue/Documents/GitHub/SCC_Intelligence/codes/Collection/twitter-scraper/scraper',
                       '--tweets=800', f'--username={username}']
            try:
                print(f"正在为 {username} 执行命令...")
                result = subprocess.run(command, check=True, text=True, capture_output=True)
                print(f"{username} 命令输出：", result.stdout)
            except subprocess.CalledProcessError as e:
                print(f"{username} 命令执行发生错误：", e.stderr)
            print(f"{username} 命令执行完成。\n")
        # 所有命令执行完毕
        print("所有命令执行完毕。")

    def rhisac_content(self):
        web_name = 'rhisac'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["rhisac"]:
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("rhisac processed:", timestamp)
                continue

            print(page_url)
            count += 1
            driver.get(page_url)
            time.sleep(3)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            WebDriverWait(driver, 10).until(EC.presence_of_element_located(
                (By.CSS_SELECTOR, ".elementor-widget.elementor-widget-theme-post-content")))
            elementor_widget = driver.find_element(By.CSS_SELECTOR,
                                                   ".elementor-widget.elementor-widget-theme-post-content")
            article_content = elementor_widget.find_element(By.CLASS_NAME, "elementor-widget-container")
            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "rhisac"), timestamp + ".txt"))
            self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

    # 从cybersecuritynews链接获取帖子内容，并将其处理并存储为文本文件
    def cybersecuritynews_content(self):
        web_name = 'cybersecuritynews'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        # 遍历每个时间戳和页面 URL
        for timestamp, postdate, page_url in self.webpage_dict["cybersecuritynews"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("cybersecuritynews processed: ", timestamp)
                continue
            filename = timestamp + ".txt"
            print('cybersecuritynews', timestamp, page_url)
            try:
                # 获取页面内容
                driver.get(page_url)
                time.sleep(3)  # 等待页面加载
                # 滚动页面到底部
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                # 等待 '.td-post-content.tagdiv-type' 元素出现
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, ".td-post-content.tagdiv-type")))
                # 查找文章内容元素
                article_content = driver.find_element(By.CSS_SELECTOR, ".td-post-content.tagdiv-type")
                # 解析网页元素
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                # 将解析后的内容写入文本文件
                self.write_text(webpage_content,
                                os.path.join(os.path.join(self.text_dir, "cybersecuritynews"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print("Error: ", filename)
                # 发生异常时，将空字符串写入文件
                # self.write_text("", os.path.join(os.path.join(self.text_dir, "cybersecuritynews"), filename))

    def tuxcare_content(self):
        web_name = 'tuxcare'
        # self.find_processed_files(os.path.join(self.text_dir, "tuxcare"))
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["tuxcare"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("tuxcare processed: ", timestamp)
                continue
            filename = timestamp + ".txt"
            print(timestamp, page_url)
            count += 1
            try:
                driver.get(page_url)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "tcl-m-content")))
                article_content = driver.find_element(By.CLASS_NAME, "tcl-m-content")
                webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
                print(webpage_content)
                self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "tuxcare"), filename))
                self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)
            except:
                print("Error: ", filename)
                # self.write_text("", os.path.join(os.path.join(self.text_dir, "tuxcare"), filename))

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
            print(timestamp, page_url)
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
            print(timestamp, page_url)
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

    def securityaffairs_content(self):
        web_name = 'securityaffairs'
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["securityaffairs"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("securityaffairs processed: ", timestamp)
                continue
            filename = timestamp + ".txt"
            print('securityaffairs', timestamp, page_url)
            count += 1
            driver.get(page_url)
            time.sleep(3)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".article-details-block.wow.fadeInUp.animated")))
            article_content = driver.find_element(By.CSS_SELECTOR, ".article-details-block.wow.fadeInUp.animated")
            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "securityaffairs"), filename))
            self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

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

    def checkpoint_content(self):
        web_name = 'checkpoint'
        # self.find_processed_files(os.path.join(self.text_dir, "checkpoint"))
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        count = 0
        for timestamp, postdate, page_url in self.webpage_dict["checkpoint"]:
            # 检查文件是否已处理
            if web_name in self.processed_files and timestamp in self.processed_files[web_name]:
                print("checkpoint processed: ", timestamp)
                continue
            filename = timestamp + ".txt"
            print(timestamp, page_url)
            count += 1
            driver.get(page_url)
            time.sleep(3)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".text.border-bottom")))
            article_content = driver.find_element(By.CSS_SELECTOR, ".text.border-bottom")
            webpage_content = self.parse_elements(driver, article_content, web_name, timestamp)
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "checkpoint"), filename))
            self.write_collected_pagelinks(timestamp, web_name, postdate, page_url)

    def reddit_content(self):
        self.client_id = ''
        self.client_secret = ''
        self.username = 'iBlueair'
        self.password = ''
        # 初始化 praw 实例
        self.reddit = praw.Reddit(
            client_id=self.client_id,  # 替换为你的客户端ID
            client_secret=self.client_secret,  # 替换为你的客户端密钥
            user_agent='SCC'  # 替换为你的用户代理字符串
        )
        self.find_processed_files(os.path.join(self.text_dir, "reddit"))
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for timestamp, page_url in self.webpage_dict["reddit"]:
            filename = timestamp + ".txt"
            if filename in self.processed_files:
                continue
            webpage_content = ""
            submission = self.reddit.submission(url=page_url)
            # 打印帖子的标题和内容
            webpage_content += submission.title + '\n' + submission.selftext + '\n'
            submission.comments.replace_more(limit=50)
            for comment in submission.comments.list():
                # 打印评论的内容
                webpage_content += comment.body + '\n'
            print(webpage_content)
            self.write_text(webpage_content, os.path.join(os.path.join(self.text_dir, "reddit"), filename))


if __name__ == '__main__':
    webpage_content = WebPageContent()
    webpage_content.read_txt()
    webpage_content.find_processed_files()
    # webpage_content.qianxin_content()
    # webpage_content.jfrog_content()
    # webpage_content.tuxcare_content()
    # webpage_content.fortinet_content()
    # webpage_content.datadoghq_content()
    # webpage_content.securityaffairs_content()
    # webpage_content.reversinglabs_content()
    # webpage_content.checkpoint_content()
    # webpage_content.rhisac_content()
    # webpage_content.socket_content()
    # webpage_content.cybersecuritynews_content()
    # webpage_content.bleepingcomputer_content()
    # webpage_content.snyk_content()
    # webpage_content.twitter_content()
    # webpage_content.reddit_content()
    # webpage_content.github_content()
    # webpage_content.medium_content()
    webpage_content.sonatype_oss_content()
    webpage_content.checkmarx_content()
    webpage_content.medium_recommand_content()  # 许多内容是members only，还有许多是error哈哈哈
    webpage_content.phylum_content()
    # webpage_content.aabbcc_content()
