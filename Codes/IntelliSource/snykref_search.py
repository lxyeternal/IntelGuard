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


import os
import csv
import math
import time
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from urllib.parse import urlparse
from Configs.config import HEADER
from multiprocessing import Pool, Manager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC


class GoogleSearch:
    def __init__(self, page_limit) -> None:
        self.page_limit = page_limit
        self.save_csvfile = "../csv/source_link.csv"
        self.maldataset_path = "/Users/blue/Documents/MalDataset/"
        self.google_link = 'https://www.google.com/search?q={}'
        self.chromedriver = '../utils/chromedriver/macarm/chromedriver'
        # 加载启动项，这里设置headless，表示不启动浏览器，只开一个监听接口获取返回值
        option = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(self.chromedriver, chrome_options="")
        self.contentdriver = webdriver.Chrome(self.chromedriver, chrome_options="")

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


class SnykBacktrace:
    def __init__(self) -> None:
        self.save_csvfile = "../csv/snyk_reflink.csv"
        self.snyk_malicious_csv = "../csv/{}_snyk_malicious.csv"
        self.chromedriver = '../utils/chromedriver/macarm/chromedriver'
        # 加载启动项，这里设置headless，表示不启动浏览器，只开一个监听接口获取返回值
        option = webdriver.ChromeOptions()
        # option.add_argument('headless')
        self.driver = webdriver.Chrome(self.chromedriver, chrome_options="")
        self.contentdriver = webdriver.Chrome(self.chromedriver, chrome_options="")


    def load_searched_pkgs(self):
        searched_pkgs = list()
        if os.path.exists(self.save_csvfile):
            with open(self.save_csvfile, encoding="ISO-8859-1") as csvfile:
                csv_reader = csv.reader(csvfile)  # 使用csv.reader读取csvfile中的文件
                for row in csv_reader:
                    pkgname = row[1]
                    searched_pkgs.append(pkgname)
            searched_pkgs = list(set(searched_pkgs))
        return searched_pkgs


    def write_csv(self, pkg_urls):
        with open(self.save_csvfile, 'a+') as f:
            csv_write = csv.writer(f)
            csv_write.writerows(pkg_urls)


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
            # 使用显式等待，等待页面中的一个或多个<a>标签出现，或者超时
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
                sitename = link.text
                content_links = self.content_links_requests(url)
                if content_links == []:
                    content_links = self.content_links_selenium(url)
                self.write_csv([[manager, pkgname, snyk_link, idx, sitename, url, content_links]])
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
    searched_unique_lst = snykbacktrace.load_searched_pkgs()
    # 需要处理的链接列表
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

def googleworker(manager_pkg_pair, shared_results, searched_unique_lst):
    linksearch_local = GoogleSearch(100)
    manager, pkg = manager_pkg_pair
    if pkg not in searched_unique_lst[manager]:
        linksearch_local.parse_search_page(manager, pkg)
        shared_results.append(pkg)  # 假设我们想记录处理过的包名
        print(f"Processed: {pkg}")

def googlemain():
    linksearch = GoogleSearch(100)
    all_pkgs = linksearch.find_pkgnames()
    searched_unique_lst = linksearch.load_searched_pkgs()
    # 构造需要处理的(manager, pkg)对的列表
    tasks = [(manager, pkg) for manager, pkgs in all_pkgs.items() for pkg in pkgs if pkg not in searched_unique_lst[manager]]
    num_processes = 10  # 你可以根据需要调整进程数量
    with Manager() as manager:
        shared_results = manager.list()  # 用于存储处理结果的列表
        with Pool(num_processes) as p:
            p.starmap(googleworker, [(task, shared_results, searched_unique_lst) for task in tasks])
        # 打印处理结果
        for result in shared_results:
            print(result)


if __name__ == '__main__':

    snykmain()
    # googlemain()