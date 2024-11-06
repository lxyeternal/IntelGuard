# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : pypi_bigquery.py
# @Project  : MalDataCollect
# Time      : 12/8/24 10:39 am
# Author    : honywen
# version   : python 3.8
# Description：
"""


from datetime import datetime
from collections import defaultdict
from google.cloud import bigquery


def query_bigquery(names):
    # 设置凭证文件路径（使用你的服务账户 JSON 凭证文件）
    # client = bigquery.Client()
    client = bigquery.Client.from_service_account_json("/Users/blue/Documents/Github/IntelliGraph/Configs/pypi-dataset-378706-8eeb053a916e.json")
    # 构建查询字符串
    # 构建查询条件
    if len(names) == 1:
        names_condition = f'name = "{names[0]}"'
    else:
        names_condition = ' OR '.join([f'name = "{name}"' for name in names])
    query = f"""
    SELECT name, version, description, author, author_email,  uploaded_via, upload_time, size, python_version, packagetype
    FROM `bigquery-public-data.pypi.distribution_metadata` 
    WHERE {names_condition}
    """
    # 执行查询
    query_job = client.query(query)
    # 获取查询结果
    results = query_job.result()
    # 解析结果并进行聚合
    aggregated_results = {}
    for row in results:
        package_name = row.name.lower()
        if package_name not in aggregated_results:
            aggregated_results[package_name] = {
                'versions': set(),
                'description': row.description,
                'author': row.author,
                'author_email': row.author_email,
                'uploaded_via': set(),
                'upload_time': set(),
                'size': set(),
                'python_version': set(),
                'packagetype': set()
            }
        # 聚合不同版本
        aggregated_results[package_name]['versions'].add(row.version)
        if row.uploaded_via is not None:
            aggregated_results[package_name]['uploaded_via'].add(row.uploaded_via)
        if row.upload_time is not None:
            aggregated_results[package_name]['upload_time'].add(row.upload_time.date())
        if row.size is not None:
            aggregated_results[package_name]['size'].add(row.size)
        if row.python_version is not None:
            aggregated_results[package_name]['python_version'].add(row.python_version)
        if row.packagetype is not None:
            aggregated_results[package_name]['packagetype'].add(row.packagetype)
    return aggregated_results



def process_package_data(package_manager_dict):
    # 合并 pypi, pip, python 对应的包列表
    combined_packages = set()
    for key in ['pypi', 'pip', 'python']:
        combined_packages.update(package_manager_dict[key])

    # 将合并后的包列表进行分块，每块包含最多 50 个包
    chunk_size = 50
    package_chunks = [list(combined_packages)[i:i + chunk_size] for i in range(0, len(combined_packages), chunk_size)]

    # 查询每个分块，并整合结果
    final_results = {}
    for chunk in package_chunks:
        chunk_results = query_bigquery(chunk)
        for package_name, data in chunk_results.items():
            if package_name not in final_results:
                final_results[package_name] = data
            else:
                # 合并版本等集合类型的数据
                final_results[package_name]['versions'].update(data['versions'])
                final_results[package_name]['uploaded_via'].update(data['uploaded_via'])
                final_results[package_name]['upload_time'].update(data['upload_time'])
                final_results[package_name]['size'].update(data['size'])
                final_results[package_name]['python_version'].update(data['python_version'])
                final_results[package_name]['packagetype'].update(data['packagetype'])
    return final_results


# if __name__ == '__main__':
#     count = 0
#     package_manager_dict = defaultdict(list)
#     # 示例数据填充 package_manager_dict
#     package_manager_dict['pypi'] = ['requests', 'bussardweg4a']
#     package_manager_dict['pip'] = ['bingchilling2', 'httops']
#     package_manager_dict['python'] = ['tkint3rs']
#
#     pypi_basic_info = process_package_data(package_manager_dict)

