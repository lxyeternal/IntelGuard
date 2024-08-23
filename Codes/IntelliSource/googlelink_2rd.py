# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : googlelink_2rd.py
# @Project  : SCC_Intelligence
# Time      : 17/4/24 8:14 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import re
import os
import csv
import time
import praw
from collections import Counter
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class GoogleLinkSecond:
    def __init__(self):
        self.google_first_files = '/Users/blue/Documents/GitHub/SCC_Intelligence/codes/Backtrace/oss_source/first_source.csv'
        self.google_first_list = []
        self.chromedriver = '../../utils/chromedriver/macarm/chromedriver'
        self.service = Service(executable_path=self.chromedriver)
        self.options = webdriver.ChromeOptions()
        self.options.add_argument("--disable-gpu")
        self.options.add_argument("--enable-javascript")
        self.webpage_links = {}
        self.processed_files = "oss_source/processed_files.csv"
        self.processed_links = {}
        self.ignore_links = [
                    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',  # 图像文件
                    '.pdf',  # PDF文件
                    '.zip', '.rar',  # 压缩文件
                    '.py', '.java', '.cpp', '.js', '.ts', '.cs', '.php'  # 编程源文件
                ]


    def read_google_first(self):
        with open(self.google_first_files, 'r') as f:
            csv_lines = csv.reader(f)
            for line in csv_lines:
                self.google_first_list.append(line[5].strip())
        element_counts = Counter(self.google_first_list)
        sorted_elements = element_counts.most_common()
        for element, count in sorted_elements:
            if count > 10:
                print(f"{element}: {count}")


    def find_processed_files(self):
        #  判断文件是否存在
        if os.path.exists(self.processed_files):
            with open(self.processed_files, 'r') as f:
                lines = csv.reader(f)
                for line in lines:
                    page_url = line[0].strip()
                    source = line[1].strip()
                    if source in self.processed_links:
                        self.processed_links[source].append(page_url)
                    else:
                        self.processed_links[source] = [page_url]

    def load_webpage_link(self):
        with open(self.google_first_files, 'r') as f:
            csv_lines = csv.reader(f)
            for line in csv_lines:
                self.google_first_list.append(line)

    def write_second_links(self, source, page_url, second_links):
        with open(self.processed_files, 'a') as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow([source, page_url, second_links])


    def extract_urls_with_requests(self, request_obj):
        links = request_obj.find_all('a') if request_obj else []
        urls = [link.get('href') for link in links if link.get('href') and not any(
            link.get('href').endswith(ext) for ext in self.ignore_links)]
        return urls

    def extract_urls_with_selenium(self, request_obj):
        # 在定位到的区域中查找所有的<a>标签
        links = request_obj.find_elements(By.TAG_NAME, 'a')
        urls = []
        # 提取非图片链接
        for link in links:
            href = link.get_attribute('href')
            if href and not any(href.endswith(ext) for ext in self.ignore_links):
                urls.append(href)
        return urls


    def phylum_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "blog.phylum.io":
                if first_link in self.processed_links["blog.phylum.io"]:
                    continue
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".gh-content.gh-canvas")))
                    article_content = driver.find_element(By.CSS_SELECTOR, ".gh-content.gh-canvas")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def sonatype_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "blog.sonatype.com":
                if first_link in self.processed_links["blog.sonatype.com"]:
                    continue
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "hs_cos_wrapper_post_body")))
                    article_content = driver.find_element(By.ID, "hs_cos_wrapper_post_body")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def checkmax_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "checkmarx.com":
                driver.get(first_link)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                try:
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".elementor-element.elementor-element-2bd10d61.elementor-widget.elementor-widget-theme-post-content")))
                    article_content = driver.find_element(By.CSS_SELECTOR,".elementor-element.elementor-element-2bd10d61.elementor-widget.elementor-widget-theme-post-content")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def jfrog_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "jfrog.com":
                if first_link in self.processed_links["blog.sonatype.com"]:
                    continue
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "entry-content")))
                    article_content = driver.find_element(By.CLASS_NAME, "entry-content")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def rhisac_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "rhisac.org":
                print(first_link)
                driver.get(first_link)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".elementor-widget.elementor-widget-theme-post-content")))
                elementor_widget = driver.find_element(By.CSS_SELECTOR, ".elementor-widget.elementor-widget-theme-post-content")
                article_content = elementor_widget.find_element(By.CLASS_NAME, "elementor-widget-container")
                webpage_content = self.extract_urls_with_selenium(article_content)
                print(webpage_content)
                self.write_second_links(first_link, domain, webpage_content)

    def medium_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "medium.com":
                try:
                    driver.get(first_link)
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
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".ch.bg.fy.fz.ga.gb")))
                    content_div = driver.find_elements(By.CSS_SELECTOR, ".ch.bg.fy.fz.ga.gb")[1]
                    page_content = self.extract_urls_with_selenium(content_div)
                    print(page_content)
                    self.write_second_links(first_link, domain, page_content)
                except:
                    pass


    def qianxin_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "tianwen.qianxin.com":
                try:
                    driver.get(first_link)
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "post-content")))
                    post_content = driver.find_element(By.CLASS_NAME, "post-content")
                    webpage_content = self.extract_urls_with_selenium(post_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def snyk_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "snyk.io":
                try:
                    print(first_link)
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "txt-rich-long")))
                    article_content = driver.find_element(By.CLASS_NAME, "txt-rich-long")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def bleepingcomputer_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.bleepingcomputer.com":
                if first_link in self.processed_links["www.bleepingcomputer.com"]:
                    continue
                print(first_link)
                driver.get(first_link)
                time.sleep(10)
                try:
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    try:
                        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "articleBody")))
                        driver.execute_script("window.stop();")  # 立即停止加载其余部分
                        article_content = driver.find_element(By.CLASS_NAME, "articleBody")
                    except:
                        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CLASS_NAME, "article_section")))
                        driver.execute_script("window.stop();")
                        article_content = driver.find_element(By.CLASS_NAME, "article_section")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def datadoghq_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.datadoghq.com":
                driver.get(first_link)
                time.sleep(3)
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "blog-content")))
                article_content = driver.find_element(By.ID, "blog-content")
                webpage_content = self.extract_urls_with_selenium(article_content)
                print(webpage_content)
                self.write_second_links(first_link, domain, webpage_content)



    def cybersecuritynews_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "cybersecuritynews.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".td-post-content.tagdiv-type")))
                    article_content = driver.find_element(By.CSS_SELECTOR, ".td-post-content.tagdiv-type")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def tuxcare_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "tuxcare.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "tcl-m-content")))
                    article_content = driver.find_element(By.CLASS_NAME, "tcl-m-content")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def reversinglabs_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.reversinglabs.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "hs_cos_wrapper_post_body")))
                    article_content = driver.find_element(By.ID, "hs_cos_wrapper_post_body")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass
    def fortinet_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.fortinet.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".aem-Grid.aem-Grid--12.aem-Grid--default--12")))
                    article_content = driver.find_element(By.CSS_SELECTOR,".aem-Grid.aem-Grid--12.aem-Grid--default--12")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def securityaffairs_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "securityaffairs.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".article-details-block.wow.fadeInUp.animated")))
                    article_content = driver.find_element(By.CSS_SELECTOR,".article-details-block.wow.fadeInUp.animated")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def checkpoint_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.checkpoint.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, ".text.border-bottom")))
                    article_content = driver.find_element(By.CSS_SELECTOR, ".text.border-bottom")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def thehackernews_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "thehackernews.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "post-body")))
                    article_content = driver.find_element(By.CLASS_NAME, "post-body")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def reddit_content(self):
        reddit = praw.Reddit(
            client_id='',  # 替换为你的客户端ID
            client_secret='',  # 替换为你的客户端密钥
            user_agent='SCC'  # 替换为你的用户代理字符串
        )
        for first_link, domain in self.google_first_list:
            if domain == "www.reddit.com":
                try:
                    post_content = ""
                    submission = reddit.submission(url=first_link)
                    post_title = submission.title
                    post_selftext = submission.selftext
                    post_content += post_title + "\n" + post_selftext + "\n"
                    for comment in submission.comments.list():
                        post_content += comment.body + "\n"
                    url_pattern = r'https?://\S+'
                    # 使用 findall 方法查找文本中所有匹配的 URLs
                    urls = re.findall(url_pattern, post_content)
                    print(urls)
                    self.write_second_links(first_link, domain, urls)
                except:
                    pass

    def cyware_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "cyware.com":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "cy-alert__description")))
                    article_content = driver.find_element(By.CLASS_NAME, "cy-alert__description")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def thenewstack_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "thenewstack.io":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "tns-post-body-content")))
                    article_content = driver.find_element(By.CLASS_NAME, "tns-post-body-content")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def securityweek_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.securityweek.com":
                if first_link in self.processed_links["www.securityweek.com"]:
                    continue
                try:
                    driver.get(first_link)
                    time.sleep(10)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "zox-post-body")))
                    article_content = driver.find_element(By.CLASS_NAME, "zox-post-body")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def theregister_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.theregister.com":
                # if first_link in self.processed_links["www.theregister.com"]:
                #     continue
                try:
                    driver.get(first_link)
                    time.sleep(10)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "body")))
                    article_content = driver.find_element(By.ID, "body")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def darkreading_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.darkreading.com":
                # if first_link in self.processed_links["www.theregister.com"]:
                #     continue
                try:
                    driver.get(first_link)
                    time.sleep(10)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "ContentModule-Wrapper")))
                    article_content = driver.find_element(By.CLASS_NAME, "ContentModule-Wrapper")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass

    def csoonline_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "www.csoonline.com":
                # if first_link in self.processed_links["www.theregister.com"]:
                #     continue
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "remove_no_follow")))
                    article_content = driver.find_element(By.ID, "remove_no_follow")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass


    def iototsecnews_content(self):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.implicitly_wait(5)
        for first_link, domain in self.google_first_list:
            if domain == "iototsecnews.jp":
                try:
                    driver.get(first_link)
                    time.sleep(3)
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "entry-content")))
                    article_content = driver.find_element(By.CLASS_NAME, "entry-content")
                    webpage_content = self.extract_urls_with_selenium(article_content)
                    print(webpage_content)
                    self.write_second_links(first_link, domain, webpage_content)
                except:
                    pass



if __name__ == '__main__':
    google_link_second = GoogleLinkSecond()
    # google_link_second.read_google_first()
    google_link_second.find_processed_files()
    google_link_second.load_webpage_link()
    # google_link_second.phylum_content()
    # google_link_second.sonatype_content()
    # google_link_second.jfrog_content()
    # google_link_second.rhisac_content()
    # google_link_second.checkmax_content()
    # google_link_second.medium_content()
    # google_link_second.qianxin_content()
    # google_link_second.snyk_content()
    # google_link_second.bleepingcomputer_content()
    # google_link_second.datadoghq_content()
    # google_link_second.cybersecuritynews_content()
    # google_link_second.tuxcare_content()
    # google_link_second.reversinglabs_content()
    # google_link_second.fortinet_content()
    # google_link_second.securityaffairs_content()
    # google_link_second.checkpoint_content()
    # google_link_second.thehackernews_content()
    # google_link_second.reddit_content()
    # google_link_second.cyware_content()
    # google_link_second.thenewstack_content()
    # google_link_second.securityweek_content()
    # google_link_second.theregister_content()
    # google_link_second.darkreading_content()
    # google_link_second.csoonline_content()
    # google_link_second.iototsecnews_content()