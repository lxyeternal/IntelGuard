# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : intvoting.py
# @Project  : SCC_Intelligence
# Time      : 29/7/24 10:51 am
# Author    : honywen
# version   : python 3.8
# Description：
"""


import numpy as np
from datetime import datetime
from collections import defaultdict, Counter


def standardize_data(data):
    standardized_data = []
    for entry in data:
        name, version, discovery_date, repository_url, method_of_attack, discoverer, impacted_systems, attack_vector, indicators_of_compromise, timestamp, source = entry
        standardized_entry = {
            "name": name,
            "version": version,
            "discovery_date": discovery_date,
            "repository_url": repository_url,
            "method_of_attack": method_of_attack,
            "discoverer": discoverer,
            "impacted_systems": impacted_systems,
            "attack_vector": attack_vector,
            "indicators_of_compromise": indicators_of_compromise.split(","),
            "timestamp": datetime.strptime(timestamp, "%Y-%m-%d"),
            "source": source
        }
        standardized_data.append(standardized_entry)
    return standardized_data


def aggregate_data(data):
    aggregated_data = defaultdict(list)
    for entry in data:
        key = entry["name"]
        aggregated_data[key].append(entry)
    return aggregated_data


def vote(entries, field):
    valid_entries = [entry[field] for entry in entries if
                     not (isinstance(entry[field], float) and np.isnan(entry[field]))]
    if not valid_entries:
        return float('nan')
    counter = Counter(valid_entries)
    most_common = counter.most_common()
    max_count = most_common[0][1]
    candidates = [item for item, count in most_common if count == max_count]
    if len(candidates) > 1:
        latest_entry = max((entry for entry in entries if entry[field] in candidates), key=lambda e: e["timestamp"])
        return latest_entry[field]
    return candidates[0]


def apply_voting_mechanism(aggregated_data):
    final_data = []
    for name, entries in aggregated_data.items():
        # 聚合相同 name 下的数据
        version = vote(entries, "version")
        repository_url = vote(entries, "repository_url")
        method_of_attack = vote(entries, "method_of_attack")
        discoverer = vote(entries, "discoverer")
        impacted_systems = vote(entries, "impacted_systems")
        attack_vector = vote(entries, "attack_vector")
        discovery_date = min(entry["discovery_date"] for entry in entries if not (isinstance(entry["discovery_date"], float) and np.isnan(entry["discovery_date"])))
        indicators_of_compromise = list(
            set([indicator for entry in entries for indicator in entry["indicators_of_compromise"]]))

        # 提取最早的时间戳并转换为字符串格式
        earliest_timestamp = min(entry["timestamp"] for entry in entries)
        earliest_timestamp_str = earliest_timestamp.strftime("%Y-%m-%d")

        final_data.append({
            "name": name,
            "version": version,
            "discovery_date": discovery_date,
            "repository_url": repository_url,
            "method_of_attack": method_of_attack,
            "discoverer": discoverer,
            "impacted_systems": impacted_systems,
            "attack_vector": attack_vector,
            "indicators_of_compromise": indicators_of_compromise,
            "timestamp": earliest_timestamp_str,
            "sources": [entry["source"] for entry in entries]
        })
    return final_data


# # 示例数据
# data = [
#     ["name1", "version1", "2024-07-01", "url1", "method1", "discoverer1", "system1", "vector1", "indicator1", "2024-07-01", "SourceA"],
#     ["name1", "version1", "2024-07-02", "url2", "method2", "discoverer2", "system2", "vector2", "indicator2", "2024-07-02", "SourceB"],
#     ["name1", "version1", "2024-07-03", "url3", "method1", "discoverer3", "system3", "vector3", "indicator3", "2024-07-03", "SourceC"],
#     ["name2", "version2", "2024-07-04", "url4", "method2", "discoverer4", "system4", "vector4", "indicator4", "2024-07-04", "SourceC"],
#     ["name3", "version1", "2024-07-05", "url5", float('nan'), "discoverer5", "system5", "vector5", "indicator5", "2024-07-05", "SourceE"]
# ]
#
# # 处理数据
# standardized_data = standardize_data(data)
# aggregated_data = aggregate_data(standardized_data)
# final_data = apply_voting_mechanism(aggregated_data)
#
# # 打印结果
# for entry in final_data:
#     print(entry)