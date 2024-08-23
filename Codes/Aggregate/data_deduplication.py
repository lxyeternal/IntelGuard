# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : data_deduplication.py
# @Project  : SCC_Intelligence
# Time      : 6/4/24 10:14 am
# Author    : honywen
# version   : python 3.8
# Description：
"""



import os
import csv

def read_csv(file_path):
    with open(file_path, "r", encoding="utf-8") as csvfile:
        csvreader = csv.reader(csvfile)
        data = [row for row in csvreader]
    return data


def remove_duplicates(data):
    # 从第一行开始，逐行检查是否有重复
    deduplicated_data = [data[0]]
    for row in data[1:]:
        if row not in deduplicated_data:
            deduplicated_data.append(row)
    return deduplicated_data
