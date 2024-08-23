# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : scan_mirrors.py
# @Project  : SCC_Intelligence
# Time      : 25/7/24 10:43 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import csv
import requests
from bs4 import BeautifulSoup
from multiprocessing import Pool, current_process
from functools import partial



class TencentMirror:
    def __init__(self):
        self.tsinghua = "https://pypi.tuna.tsinghua.edu.cn/simple"
        self.aliyun = "https://mirrors.aliyun.com/pypi/simple"
        self.tencent = "https://mirrors.cloud.tencent.com/pypi/simple"
        self.netease = "https://mirrors.163.com/pypi/simple"
        self.douban = "https://pypi.doubanio.com/simple"
        self.sustech = "https://pypi.mirrors.sustech.edu.cn/simple"
        self.huawei = "https://repo.huaweicloud.com/repository/pypi/simple"
        self.bfsu = "https://mirrors.bfsu.edu.cn/pypi/web/simple"
        self.mirror_baselink = {
            "Tsinghua": "https://pypi.tuna.tsinghua.edu.cn/",
            "Aliyun": "https://mirrors.aliyun.com/pypi/",
            "Tencent": "https://mirrors.cloud.tencent.com/pypi/",
            "Netease": "https://mirrors.163.com/pypi/",
            "Douban": "https://mirrors.cloud.tencent.com/pypi/packages/",
            "Huawei": "https://repo.huaweicloud.com/artifactory/pypi-public/",
            "Bfsu": "https://mirrors.bfsu.edu.cn/pypi/web/",
            "Sustech": "https://pypi.mirrors.sustech.edu.cn/"
        }
        self.malicious_pkgs = []
        self.loaded_pkgs = []

    def fetch_data(self, mirror, url):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                # 如果镜像是Tsinghua或Ustc，递归访问所有链接
                if mirror in ["Tsinghua", "Bfsu"]:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    for a in soup.find_all('a'):
                        link = a.get('href')
                        if link:
                            if link.startswith("http:"):
                                download_link = link
                            elif link.startswith("../../"):
                                download_link = self.mirror_baselink[mirror] + link.replace("../../", "")
                            else:
                                download_link = self.mirror_baselink[mirror] + link.replace("../../", "")
                            try:
                                file_response = requests.get(download_link, timeout=5)
                                if file_response.status_code == 200 and "404 not found" not in file_response.text.lower():
                                    return True  # 一旦找到可访问的链接，立即返回True
                            except requests.exceptions.RequestException:
                                continue
                    return False  # 如果所有链接都无法访问，返回False
                else:
                    # 对于其他镜像，只需检查状态码是否为200且内容不包含"404"
                    if "404 not found" not in response.text.lower():
                        return True
                    return False
            else:
                return False  # 如果初始URL无法访问，返回False
        except requests.exceptions.RequestException as e:
            return False

    def load_checked_packages(self):
        if not os.path.exists("mirror_check.csv"):
            return
        with open("mirror_check.csv", "r") as fr:
            csv_reader = csv.reader(fr)
            for row in csv_reader:
                self.loaded_pkgs.append(row[1].strip().lower())
        self.loaded_pkgs = list(set(self.loaded_pkgs))


    def load_malicious_pkgs(self):
        with open("/Users/blue/Documents/GitHub/SCC_Intelligence/codes/Analysis/rq1/rq1_csv/our_database_half.csv", "r") as fr:
            csv_reader = csv.reader(fr)
            for row in csv_reader:
                pkgname = row[0].strip().lower()
                manager = row[1].strip().lower()
                if manager == "pypi":
                    self.malicious_pkgs.append(pkgname)
        self.malicious_pkgs = list(set(self.malicious_pkgs))
        print("Total malicious packages: ", len(self.malicious_pkgs))

    def write_csv(self, data):
        file_path = "mirror_check.csv"
        file_exists = os.path.isfile(file_path)
        with open(file_path, "a", newline='') as fw:
            csv_writer = csv.writer(fw)
            if not file_exists:
                csv_writer.writerow(["mirror", "package name", "package version", "mirror link"])
            csv_writer.writerow(data)

    def check_package_in_mirror(self, pkgname):
        if pkgname in self.loaded_pkgs:
            return
        for mirror, link in zip(
            ["Tsinghua", "Aliyun", "Tencent", "Netease", "Douban", "Sustech", "Huawei", "Bfsu"],
            [self.tsinghua, self.aliyun, self.tencent, self.netease, self.douban, self.sustech, self.huawei, self.bfsu]
        ):
            pkg_link = os.path.join(link, pkgname)
            flag = self.fetch_data(mirror, pkg_link)
            print(mirror, pkgname, flag, pkg_link)
            if flag:
                self.write_csv([mirror, pkgname, "", pkg_link])
                return
    def process_package_group(self, package_group):
        for index, pkgname in enumerate(package_group):
            print(f"Process {current_process().name} is processing package {index} of {len(package_group)}")
            self.check_package_in_mirror(pkgname)

    def check_exist(self, num_processes):
        chunk_size = len(self.malicious_pkgs) // num_processes
        package_groups = [self.malicious_pkgs[i:i + chunk_size] for i in range(0, len(self.malicious_pkgs), chunk_size)]
        pool = Pool(processes=num_processes)
        process_func = partial(self.process_package_group)
        pool.map(process_func, package_groups)
        pool.close()
        pool.join()



if __name__ == '__main__':
    tencent = TencentMirror()
    tencent.load_malicious_pkgs()
    tencent.load_checked_packages()
    tencent.check_exist(10)  # 使用CPU的核数量作为进程数