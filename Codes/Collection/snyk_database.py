# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : parse_snyk_database.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 01:45
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import csv
import copy
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service


class SnykDatabase:
    def __init__(self):
        # 初始化相关路径和变量
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.record_file = os.path.join(project_dir, "Dataset/CSV/snyk_pkginfo.csv")
        self.chromedriver = os.path.join(project_dir, "utils/chromedriver/macarm/chromedriver")
        self.snyk_baseurl = "https://security.snyk.io/"
        self.synk_vulurl = "https://security.snyk.io/vuln/"
        self.stop_file = "snyk_stop.txt"
        self.old_stop_packages = dict()
        self.read_stop_file()
        self.new_stop_packages = copy.deepcopy(self.old_stop_packages)
        # 加载启动项
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(service=service, options=options)
        self.infodriver = webdriver.Chrome(service=service, options=options)

    def read_stop_file(self):
        # 读取停止文件
        with open(self.stop_file, "r") as file:
            for line in file:
                key, value = line.strip().split('\t')
                self.old_stop_packages[key] = value

    def write_stop_file(self):
        # 写入停止文件
        with open(self.stop_file, "w") as file:
            for key, value in self.new_stop_packages.items():
                file.write(f"{key}\t{value}\n")

    def write_snyk_pkginfo(self, snyk_pkginfo):
        # 写入CSV文件
        if not os.path.exists(self.record_file):
            csv_header = ['manager', 'package_name', 'snyk_link', 'security_score', 'affected_version', 'install_type',
                          'cve', 'cwe', 'fix_method', 'overview', 'update_date', 'package_type', 'ref_links',
                          'Attack Vector (AV)', 'Attack Complexity (AC)', 'Attack Requirements (AT)', 'Privileges Required (PR)',
                          'User Interaction (UI)', 'Confidentiality (VC)', 'Integrity (VI)', 'Availability (VA)',
                          'Confidentiality (SC)', 'Integrity (SI)', 'Availability (SA)']
            with open(self.record_file, 'w', newline='') as f:
                csv_writer = csv.writer(f)
                csv_writer.writerow(csv_header)
        with open(self.record_file, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(snyk_pkginfo)

    def parse_snyk_database(self, manager, page_index):
        # 解析Snyk数据库
        snyk_pkgs = []
        self.driver.get(os.path.join(self.synk_vulurl, manager, page_index))
        self.driver.implicitly_wait(10)
        vulns_table = self.driver.find_element(By.CLASS_NAME, "vulns-table")
        table_tbody = vulns_table.find_element(By.CLASS_NAME, "vue--table__tbody")
        vue_table_row = table_tbody.find_elements(By.TAG_NAME, "tr")

        for row_index, row in enumerate(vue_table_row):
            row_tds = row.find_elements(By.TAG_NAME, "td")
            pkg_collected = False
            for td_index, td in enumerate(row_tds):
                if td_index == 0:
                    td_type = td.text.split("\n")[1].strip()
                    td_href = td.find_element(By.TAG_NAME, "a").get_attribute('href')
                    if td_type != 'Malicious Package':
                        break
                if td_index == 1:
                    pkgname = td.text.split(" ")[0].strip()
                    pkgversion = td.text.replace(pkgname, "").strip()
                    if pkgname == self.old_stop_packages.get(manager):
                        pkg_collected = True
                        break
                    if row_index == 0:
                        self.new_stop_packages[manager] = pkgname

                    snyk_pkgs.append([td_href, pkgname, pkgversion])
            if pkg_collected:
                break
        return snyk_pkgs

    def snyk_pkginfo(self, manager, pkg_info_url, pkgname, pkgversion):
        basic_info = {
            "manager": manager,
            "package_name": pkgname,
            "snyk_link": pkg_info_url,
            "security_score": "9.3",
            "affected_version": pkgversion,
            "install_type": manager,
            "cve": "",
            "cwe": "",
            "fix_method": "",
            "overview": "",
            "update_date": "",
            "package_type": "",
            "ref_links": ""
        }

        # 处理网页内容，获取各项信息
        try:
            self.infodriver.get(pkg_info_url)
            self.driver.implicitly_wait(10)
            vuln_page_body_wrapper = self.infodriver.find_element(By.CLASS_NAME, "vuln-page__body-wrapper")

            left_div = vuln_page_body_wrapper.find_element(By.CLASS_NAME, "left")
            vuln_info_block = left_div.find_element(By.CLASS_NAME, "vuln-info-block")

            basic_info["update_date"] = vuln_info_block.find_element(By.XPATH, "h4[@data-snyk-test='formatted-date']").text
            basic_info["package_type"] = vuln_info_block.find_element(By.XPATH, "span[@data-snyk-test='malicious-badge']").text
            basic_info["cve"] = vuln_info_block.find_element(By.XPATH, "span[@data-snyk-test='no-cve']").text
            basic_info["cwe"] = vuln_info_block.find_element(By.XPATH, "span[@data-snyk-test='cwe']").text.replace("OPEN THIS LINK IN A NEW TAB", "").strip()

            vuln_fix_content = left_div.find_elements(By.CLASS_NAME, "markdown-section")
            basic_info["fix_method"] = vuln_fix_content[0].find_element(By.CLASS_NAME, "vue--prose").text
            basic_info["overview"] = vuln_fix_content[1].find_element(By.CLASS_NAME, "vue--prose").text

            ref_links = []
            relink_block = left_div.find_elements(By.CSS_SELECTOR, ".vue--markdown-to-html.markdown-description")[2]
            li_tags = relink_block.find_elements(By.TAG_NAME, "li")
            for li_tag in li_tags:
                link_text = li_tag.find_element(By.TAG_NAME, "a").text
                link_href = li_tag.find_element(By.TAG_NAME, "a").get_attribute("href")
                ref_links.append(f"{link_text}: {link_href}")
            basic_info["ref_links"] = "; ".join(ref_links)
        except Exception as e:
            print(f"Error processing package {pkgname}: {e}")

        # 处理CVSS数据
        cvss_info = {
            "Attack Vector (AV)": "",
            "Attack Complexity (AC)": "",
            "Attack Requirements (AT)": "",
            "Privileges Required (PR)": "",
            "User Interaction (UI)": "",
            "Confidentiality (VC)": "",
            "Integrity (VI)": "",
            "Availability (VA)": "",
            "Confidentiality (SC)": "",
            "Integrity (SI)": "",
            "Availability (SA)": ""
        }
        try:
            cvss_block = left_div.find_element(By.CLASS_NAME, "vue--block-expandable__content")
            vendorcvss__container = cvss_block.find_element(By.CLASS_NAME, "vendorcvss__container")
            vendorcvss__list_item = vendorcvss__container.find_elements(By.CLASS_NAME, "vendorcvss__list_item")
            for cvss_item in vendorcvss__list_item:
                cvss_item_name = cvss_item.find_element(By.CLASS_NAME, "cvss-details-item__label_tooltip").text
                cvss_item_value = cvss_item.find_element(By.CLASS_NAME, "cvss-details-item__value").text
                if cvss_item_name in cvss_info:
                    cvss_info[cvss_item_name] = cvss_item_value
        except Exception as e:
            print(f"Error processing CVSS info for {pkgname}: {e}")

        # 将basic_info和cvss_info合并
        combined_info = {**basic_info, **cvss_info}

        # 生成表头对应的顺序列表
        csv_header = ['manager', 'package_name', 'snyk_link', 'security_score', 'affected_version', 'install_type',
                      'cve', 'cwe', 'fix_method', 'overview', 'update_date', 'package_type', 'ref_links',
                      'Attack Vector (AV)', 'Attack Complexity (AC)', 'Attack Requirements (AT)', 'Privileges Required (PR)',
                      'User Interaction (UI)', 'Confidentiality (VC)', 'Integrity (VI)', 'Availability (VA)',
                      'Confidentiality (SC)', 'Integrity (SI)', 'Availability (SA)']
        formatted_info = [combined_info.get(header, "") for header in csv_header]
        self.write_snyk_pkginfo(formatted_info)

    def run_collection(self):
        for page_index in range(1, 10):
            for manager in ["npm", "pip"]:
                snyk_pkgs = self.parse_snyk_database(manager, str(page_index))
                for snyk_pkg in snyk_pkgs:
                    self.snyk_pkginfo(manager, snyk_pkg[0], snyk_pkg[1], snyk_pkg[2])
            # 在所有 manager 的 new_stop_packages 都更新后再写入文件
        self.write_stop_file()


if __name__ == '__main__':
    snyk = SnykDatabase()
    snyk.run_collection()

