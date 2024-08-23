# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : data_completion.py
# @Project  : PMonitor
# Time      : 2023/10/22 17:30
# Author    : honywen
# version   : python 3.8
# Description：
"""


import csv
import requests
from Configs.config import HEADER
from bs4 import BeautifulSoup
from selenium import webdriver
from urllib.parse import urlparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support import expected_conditions as EC


class DataCompletion:
    def __init__(self) -> None:
        self.input_csv = "../csv/snyk_reflink.csv"
        self.output_csv = "../csv/snyk_reflink-1.csv"
        self.chromedriver = '../utils/chromedriver/macarm/chromedriver'
        self.contentdriver = webdriver.Chrome(self.chromedriver, chrome_options="")


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

    def fill_links(self):
        with open(self.input_csv, 'r', newline='', encoding='utf-8') as csvfile, \
                open(self.output_csv, 'w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(csvfile)
            writer = csv.writer(outfile)
            # Write the header
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                content_links = eval(row[6])  # Convert the string representation of a list to an actual list
                if not content_links:  # if content_links is empty
                    print(f"Fetching content links for {row[5]}")
                    new_links = self.content_links_requests(row[5])
                    if new_links == []:
                        new_links = self.content_links_selenium(row[5])
                    row[6] = new_links  # Convert the list back to a string representation
                writer.writerow(row)


    def extract_morelinks(self):
        with open(self.input_csv, 'r', newline='', encoding='utf-8') as csvfile, \
                open(self.output_csv, 'w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(csvfile)
            writer = csv.writer(outfile)
            # Write the header
            header = next(reader)
            writer.writerow(header)
            for row in reader:
                content_links = eval(row[6])  # Convert the string representation of a list to an actual list
                for content_link in content_links:
                    new_links = self.content_links_requests(content_link)
                    if new_links == []:
                        new_links = self.content_links_selenium(content_link)
                    row[7] = new_links  # Convert the list back to a string representation
                writer.writerow(row)



if __name__ == '__main__':
    datacompletion = DataCompletion()
    datacompletion.fill_links()
