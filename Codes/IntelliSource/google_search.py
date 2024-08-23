# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : google_search.py
# @Project  : PMonitor
# Time      : 2023/10/26 21:44
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import csv
import sys
import math
import time
import requests
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup
from selenium import webdriver
from urllib.parse import urlparse
from Configs.config import HEADER
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC


class GoogleSelenium:
    def __init__(self, page_limit) -> None:
        self.page_limit = page_limit
        self.save_csvfile = "../csv/source_link.csv"
        self.maldataset_path = "/Users/blue/Documents/MalDataset/"
        self.google_link = 'https://www.google.com/search?q={}'
        self.chromedriver = '../utils/chromedriver/macarm/chromedriver'
        # 加载启动项，这里设置headless，表示不启动浏览器，只开一个监听接口获取返回值
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        # options.add_argument('--headless')
        # options.add_argument('--no-sandbox')
        # options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(service=service, options=options)
        self.infodriver = webdriver.Chrome(service=service, options=options)

    def load_searched_pkgs(self):
        searched_pkgs = {"pypi": [], "npm": []}
        if os.path.exists("/Users/blue/Documents/LLMCTI/codes/PMonitor/csv/google.txt"):
            with open("/Users/blue/Documents/LLMCTI/codes/PMonitor/csv/google.txt", encoding="utf-8-sig") as txtfile:
                for line in txtfile:
                    manager, pkgname = line.strip().split(',')  # 假设数据之间是由逗号分隔的
                    searched_pkgs[manager].append(pkgname)
        return searched_pkgs


    def save_txt(self, manager, pkgname):
        with open("/Users/blue/Documents/LLMCTI/codes/PMonitor/csv/google.txt", 'a', encoding="utf-8-sig") as txtfile:
            txtfile.write(manager+","+pkgname+"\n")


    def find_pkgnames(self):
        all_pkgs = dict()
        for manager in ["pypi", "npm"]:
            pkgnames = os.listdir(os.path.join(self.maldataset_path, manager))
            all_pkgs[manager] = pkgnames
        return all_pkgs


    def write_csv(self, pkg_urls):
        folder = os.path.exists(self.save_csvfile)
        with open(self.save_csvfile, 'a+') as f:
            #  文件不存在，写表头
            # if not folder:
            #     csv_header = ['manager', 'package', 'google_index', 'site_name', 'google_url', 'content_urls']
            #     csv_write = csv.writer(f)
            #     csv_write.writerow(csv_header)
            csv_write = csv.writer(f)
            csv_write.writerows(pkg_urls)


    def bulit_header(self, url):
        parsed_url = urlparse(url)
        # 获取域名
        referer = "{}://{}".format(parsed_url.scheme, parsed_url.netloc)
        HEADER["Referer"] = referer

    def content_links_selenium(self, url):
        try:
            self.contentdriver.set_page_load_timeout(30)
            self.contentdriver.get(url)
            WebDriverWait(self.contentdriver, 30).until(EC.presence_of_element_located((By.TAG_NAME, "a")))
            all_links = self.contentdriver.find_elements(By.TAG_NAME, "a")
            content_links = [link.get_attribute("href") for link in all_links if link.get_attribute("href")]
            return content_links
        except TimeoutException:
            print("Timed out waiting for page to load")
            return []


    def content_links_requests(self, url):
        self.bulit_header(url)
        headers = HEADER
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            all_links = soup.find_all('a', href=True)
            content_links = [link['href'] for link in all_links]
            return content_links
        except requests.RequestException as e:
            print(f"Error fetching the page: {e}")
            return []


    def parse_search_page(self, manager, pkg):
        search_keyword = "malicious " + manager + " " + pkg
        self.driver.get(self.google_link.format(search_keyword))
        for _ in range(7):
            self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)
        if self.page_limit >= 60:
            click_count = math.ceil((self.page_limit - 60) / 10)
            for _ in range(click_count):
                try:
                    more_button = self.driver.find_element(By.CSS_SELECTOR, '.GNJvt.ipz2Oe')
                    more_button.click()
                    time.sleep(1)
                except NoSuchElementException:
                    break
        # 使用WebDriverWait等待元素加载
        WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.ID, "center_col")))
        center_col = self.driver.find_element(By.CSS_SELECTOR, 'div.s6JM6d#center_col')
        mjjyud_all = center_col.find_elements(By.CLASS_NAME, "MjjYud")
        for idx, mjjyud in enumerate(mjjyud_all):
            if self.page_limit != -1 and idx >= self.page_limit:
                break
            try:
                uwcknb = mjjyud.find_element(By.CSS_SELECTOR, 'a[jsname="UWckNb"]')
                sitename = uwcknb.find_element(By.CLASS_NAME, "VuuXrf").text
                url = uwcknb.get_attribute('href')
                content_links = self.content_links_requests(url)
                if content_links == []:
                    content_links = self.content_links_selenium(url)
                self.write_csv([[manager, pkg, idx, sitename, url, str(content_links)]])
            except:
                pass
        self.save_txt(manager, pkg)




class GoogleAPI:
    def __init__(self):
        self.cse_id = "f1513fab3c7cb4cdd"
        self.api_key = ""
        self.google_error_path = "../csv/google_error.txt"
        self.maldataset_path = "/Users/blue/Documents/MalDataset/"
        self.save_csvfile = "../csv/google_source.csv"
        self.baseurl = "https://www.googleapis.com/customsearch/v1?q={}&key={}&cx={}&start={}"



    def find_pkgnames(self):
        all_pkgs = dict()
        for manager in ["pypi", "npm"]:
            pkgnames = os.listdir(os.path.join(self.maldataset_path, manager))
            if manager == "npm":
                pkgnames = [pkgname.replace("##", "/") for pkgname in pkgnames]
            all_pkgs[manager] = pkgnames
        return all_pkgs


    def parse_txt(self):
        searched_pkgs = {"npm":[], "pypi":[]}
        with open(self.google_error_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                elements = line.strip().split(',')
                project = elements[0]
                pkgname = elements[1]
                searched_pkgs[project].append(pkgname)
        return searched_pkgs


    def write_csv(self, pkg_urls):
        with open(self.save_csvfile, 'a+', encoding='utf-8-sig') as f:
            csv_write = csv.writer(f)
            csv_write.writerows(pkg_urls)

    def write_flag(self, manager, pkgname, start, flag):
        with open(self.google_error_path, 'a+') as file:
            file.write(f"{manager},{pkgname},{start},{flag}\n")


    def google_search(self, manager, pkg, start=1):
        search_keyword = '"' + pkg + '" ' + '"malicious"' + ' "' + manager + '"'
        url = self.baseurl.format(search_keyword, self.api_key, self.cse_id, start)
        print(url)
        max_retries = 3
        delay_between_retries = 5  # in seconds
        response = None  # 在这里初始化response变量
        for _ in range(max_retries):
            try:
                response = requests.get(url)
                response.raise_for_status()  # 如果响应的HTTP状态码不是200，则抛出异常
                self.write_flag(manager, pkg, start, "success")
                print(manager, pkg, start, "success")
                break  # 如果请求成功，则退出循环
            except requests.RequestException as e:
                print(f"Error occurred: {e}. Retrying...")
                time.sleep(delay_between_retries)
        else:  # 所有重试都失败后
            print(f"Failed to retrieve the content after {max_retries} attempts.")
            self.write_flag(manager, pkg, start, "error")
            print(manager, pkg, start, "error")
            return {}
        return response.json()


    def get_first_100_results(self, manager, pkg):
        results = []
        for i in range(0, 10):  # 10次请求，每次10个结果
            start = 1 + i * 10
            try:
                time.sleep(5)
                res = self.google_search(manager, pkg, start)
                items = res.get("items", [])
                if not items:  # 如果items为空，直接跳出循环
                    break
                for item_index, item in enumerate(items):
                    title = item["title"]
                    link = item["link"]
                    snippet = item["snippet"]
                    displayLink = item["displayLink"]
                    index = start + item_index
                    self.write_csv([[manager, pkg, index, title, link, displayLink, snippet]])
                if len(items) < 10:  # 如果items的长度小于10，说明已经没有更多的结果了
                    break
            except:
                pass
        return results


    def googlemain(self):
        searched_pkgs = self.parse_txt()
        all_pkgs = self.find_pkgnames()
        for manager, pkgs in all_pkgs.items():
            for idx, manager_pkg in enumerate(pkgs):
                if manager_pkg in searched_pkgs[manager]:
                    continue
                self.get_first_100_results(manager, manager_pkg)




class GoogleSecond:
    def __init__(self):
        self.raw_csvfile = "../csv/google_source.csv"
        self.new_csvfile = "../csv/google_source_new.csv"
        self.chromedriver = '../utils/chromedriver/macarm/chromedriver'
        # 加载启动项，这里设置headless，表示不启动浏览器，只开一个监听接口获取返回值
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        # options.add_argument('--headless')
        # options.add_argument('--no-sandbox')
        # options.add_argument('--disable-dev-shm-usage')
        self.contentdriver = webdriver.Chrome(service=service, options=options)
        self.searched_pkgs = list()


    def write_csv(self, pkg_urls):
        with open(self.new_csvfile, 'a+', encoding="utf-8-sig") as f:
            csv_write = csv.writer(f)
            csv_write.writerow(pkg_urls)


    def read_csv(self):
        # 提高字段大小限制
        csv.field_size_limit(sys.maxsize)
        with open(self.new_csvfile, 'r', encoding="utf-8-sig") as csvfile:
            csv_reader = csv.reader(csvfile)  # 使用csv.reader读取csvfile中的文件
            for idx, row in enumerate(csv_reader):
                self.searched_pkgs.append(row[0]+row[1]+str(row[2]))


    def bulit_header(self, url):
        parsed_url = urlparse(url)
        # 获取域名
        referer = "{}://{}".format(parsed_url.scheme, parsed_url.netloc)
        HEADER["Referer"] = referer


    def content_links_selenium(self, url):
        try:
            self.contentdriver.set_page_load_timeout(30)
            self.contentdriver.get(url)
            # 使用显式等待，等待页面中的一个或多个<a>标签出现，或者超时
            WebDriverWait(self.contentdriver, 30).until(EC.presence_of_element_located((By.TAG_NAME, "a")))
            all_links = self.contentdriver.find_elements(By.TAG_NAME, "a")
            try:
                content_links = [link.get_attribute("href") for link in all_links if link.get_attribute("href")]
                return content_links
            except:
                return []
        except TimeoutException:
            print("Timed out waiting for page to load")
            return []


    def content_links_requests(self, url):
        self.bulit_header(url)
        headers = HEADER
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            all_links = soup.find_all('a', href=True)
            content_links = [link['href'] for link in all_links]
            return content_links
        except requests.RequestException as e:
            print(f"Error fetching the page: {e}")
            return []

    def second_search(self):
        with open(self.raw_csvfile, encoding="utf-8-sig") as csvfile:
            csv_reader = csv.reader(csvfile)  # 使用csv.reader读取csvfile中的文件
            for idx, row in enumerate(csv_reader):
                if idx < 11864:
                    continue
                try:
                    if row[0]+row[1]+str(row[2]) in self.searched_pkgs:
                        continue
                    print(idx)
                    first_url = row[4]
                    content_links = self.content_links_requests(first_url)
                    if content_links == []:
                        content_links = self.content_links_selenium(first_url)
                    if content_links:
                        row.append(str(content_links))
                        self.write_csv(row)
                except:
                    pass


def calculate_frequency_of_frequencies(csv_file):
    # 设置Pandas的显示选项
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    # 读取CSV文件，指定没有表头
    df = pd.read_csv(csv_file, header=None)
    # 使用第二列（索引为1）
    column_data = df[1]
    # 统计第二列中每个元素的出现次数
    element_counts = column_data.value_counts()
    # 统计次数的出现次数
    frequency_of_frequencies = element_counts.value_counts()
    # 计算中位数
    median = np.median(frequency_of_frequencies)
    print("每个元素出现的次数：\n", element_counts)
    print("\n次数的出现次数：\n", frequency_of_frequencies)
    print("\n中位数：", median)




# if __name__ == '__main__':
#     googlesecond = GoogleSecond()
#     googlesecond.read_csv()
#     googlesecond.second_search()
    # googleapi = GoogleAPI()
    # googleapi.googlemain()