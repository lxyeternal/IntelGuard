#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : test.py
# @Project  : IntelliGraph
# Time      : 27/8/24 4:19 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import json
from collections import defaultdict
from py2neo import Graph, Node, Relationship
from Codes.Collection.pypi_bigquery import process_package_data


# Connect to Neo4j (assuming it's running locally with default settings)
graph = Graph("bolt://localhost:7687", auth=("neo4j", "12345678"), name="neo4j")
# # Clear the existing graph
graph.delete_all()


# Helper function to create or merge nodes and relationships based on your specified entities
def create_package_graph(package_data, source_name, postdate):
    package_names = package_data.get('package_name')

    # Check if package_names is a list or a string
    if isinstance(package_names, str):
        package_names = [package_names]  # Convert string to list for consistency

    # Process each package name individually
    for package_name in package_names:
        if not package_name:
            print(f"Skipping entry with missing package_name from source: {source_name}")
            continue

        # Merge package node (to avoid duplication)
        package_node = Node("Package", name=package_name)
        graph.merge(package_node, "Package", "name")

        # Create or merge a source node for the data source (e.g., medium_recommand)
        source_node = Node("Source", name=source_name)
        graph.merge(source_node, "Source", "name")

        # Create a relationship between the source and the package (if not already exists)
        rel = Relationship(source_node, "CONTAINS_PACKAGE", package_node)
        graph.merge(rel)

        # Add postdate to the package node if available
        if postdate:
            package_node['postdate'] = postdate
            graph.push(package_node)

        # Add other details and relationships (merge to avoid duplicates)
        if 'package_version' in package_data:
            package_node['version'] = package_data['package_version']
            graph.push(package_node)

        if 'package_manager' in package_data:
            pm_node = Node("PackageManager", name=package_data['package_manager'][0])  # Assuming list
            graph.merge(pm_node, "PackageManager", "name")
            rel = Relationship(package_node, "HOSTED_ON", pm_node)
            graph.merge(rel)

        if 'affected_platform' in package_data:
            for platform in package_data['affected_platform']:
                platform_node = Node("Platform", name=platform)
                graph.merge(platform_node, "Platform", "name")
                rel = Relationship(package_node, "AFFECTS_PLATFORM", platform_node)
                graph.merge(rel)

        if 'publisher_name' in package_data:
            publisher_node = Node("Publisher", name=package_data['publisher_name'])
            graph.merge(publisher_node, "Publisher", "name")
            rel = Relationship(package_node, "PUBLISHED_BY", publisher_node)
            graph.merge(rel)

        if 'impact' in package_data:
            for impact in package_data['impact']:
                impact_node = Node("Impact", description=impact)
                graph.merge(impact_node, "Impact", "description")
                rel = Relationship(package_node, "HAS_IMPACT", impact_node)
                graph.merge(rel)

        if 'IOC' in package_data:
            for ioc in package_data['IOC']:
                ioc_node = Node("IOC", indicator=ioc)
                graph.merge(ioc_node, "IOC", "indicator")
                rel = Relationship(package_node, "HAS_IOC", ioc_node)
                graph.merge(rel)

        if 'mitigation_measures' in package_data:
            for measure in package_data['mitigation_measures']:
                measure_node = Node("Mitigation", description=measure)
                graph.merge(measure_node, "Mitigation", "description")
                rel = Relationship(package_node, "HAS_MITIGATION", measure_node)
                graph.merge(rel)

        if 'malicious_code_embedded_file' in package_data:
            for file_name in package_data['malicious_code_embedded_file']:
                file_node = Node("MaliciousFile", name=file_name)
                graph.merge(file_node, "MaliciousFile", "name")
                rel = Relationship(package_node, "EMBEDDED_IN", file_node)
                graph.merge(rel)

        if 'functionality' in package_data:
            for func in package_data['functionality']:
                func_node = Node("Functionality", description=func)
                graph.merge(func_node, "Functionality", "description")
                rel = Relationship(package_node, "HAS_FUNCTIONALITY", func_node)
                graph.merge(rel)

        if 'code_level_techniques' in package_data:
            for technique in package_data['code_level_techniques']:
                technique_node = Node("Technique", description=technique)
                graph.merge(technique_node, "Technique", "description")
                rel = Relationship(package_node, "USES_CODE_LEVEL_TECHNIQUE", technique_node)
                graph.merge(rel)

        if 'operational_techniques' in package_data:
            for technique in package_data['operational_techniques']:
                op_tech_node = Node("OperationalTechnique", description=technique)
                graph.merge(op_tech_node, "OperationalTechnique", "description")
                rel = Relationship(package_node, "USES_OPERATIONAL_TECHNIQUE", op_tech_node)
                graph.merge(rel)

        if 'malicious_execute_phase' in package_data:
            for phase in package_data['malicious_execute_phase']:
                phase_node = Node("ExecutionPhase", description=phase)
                graph.merge(phase_node, "ExecutionPhase", "description")
                rel = Relationship(package_node, "HAS_EXECUTION_PHASE", phase_node)
                graph.merge(rel)

        if 'related_malicious_code_snippet' in package_data:
            for snippet in package_data['related_malicious_code_snippet']:
                snippet_node = Node("CodeSnippet", code=snippet)
                graph.merge(snippet_node, "CodeSnippet", "code")
                rel = Relationship(package_node, "CONTAINS_SNIPPET", snippet_node)
                graph.merge(rel)

        if 'affected_libraries' in package_data:
            for lib in package_data['affected_libraries']:
                lib_node = Node("Library", name=lib)
                graph.merge(lib_node, "Library", "name")
                rel = Relationship(package_node, "AFFECTS_LIBRARY", lib_node)
                graph.merge(rel)

        if 'distribution_method' in package_data:
            dist_node = Node("DistributionMethod", description=package_data['distribution_method'])
            graph.merge(dist_node, "DistributionMethod", "description")
            rel = Relationship(package_node, "DISTRIBUTED_VIA", dist_node)
            graph.merge(rel)

        if 'malicious_behavior_pattern' in package_data:
            pattern_node = Node("BehaviorPattern", description=package_data['malicious_behavior_pattern'])
            graph.merge(pattern_node, "BehaviorPattern", "description")
            rel = Relationship(package_node, "EXHIBITS_BEHAVIOR", pattern_node)
            graph.merge(rel)

        if 'attack_vector' in package_data:
            vector_node = Node("AttackVector", description=package_data['attack_vector'])
            graph.merge(vector_node, "AttackVector", "description")
            rel = Relationship(package_node, "USES_ATTACK_VECTOR", vector_node)
            graph.merge(rel)


def extract_timestamp(json_file_stamp):
    # Read the txt file content
    with open("/Users/blue/Documents/Github/IntelliGraph/Codes/Collection/pagelinks/collected_pagelinks.txt", 'r') as file:
        lines = file.readlines()
    for line in lines:
        columns = line.strip().split("\t")
        # Compare the json_file_stamp with the first column of the line
        if columns[0] == json_file_stamp:
            # Return the third column, which is the timestamp
            return columns[2]
    # If no match is found, return None
    return None


def extract_package_names(data, package_names):
    # 检查数据的类型，并根据类型进行处理
    if isinstance(data, dict):
        # 如果是字典，尝试获取 package_name，如果没有则继续递归
        if 'package_name' in data:
            package_names.append(data['package_name'])
        else:
            for key, value in data.items():
                extract_package_names(value, package_names)
    elif isinstance(data, list):
        # 如果是列表，递归处理每个元素
        for item in data:
            extract_package_names(item, package_names)

def find_and_extract_package_names(data, package_names_list):
    # 尝试从不同的顶层键中提取数据
    if 'package_name' in data:
        package_names_list.append(data)
    else:
        for key in ['output', 'result', 'malicious_packages', 'packages']:
            if key in data:
                if isinstance(data[key], list):
                    for item in data[key]:
                        package_names_list.append(item)
                else:
                    package_names_list.append(data[key])


def update_graph_with_basic_info(package_manager_dict):
    pypi_basic_info = process_package_data(package_manager_dict)
    for package_name, package_info in pypi_basic_info.items():
        package_node = graph.nodes.match("Package", name=package_name).first()
        if package_node:
            # Update versions, merge and deduplicate
            existing_versions = set(package_node.get('version', []))
            new_versions = set(package_info['versions'])
            package_node['version'] = list(existing_versions.union(new_versions))
            # Update other fields
            package_node['uploaded_via'] = package_info['uploaded_via']
            package_node['upload_time'] = package_info['upload_time']
            package_node['size'] = package_info['size']
            package_node['python_version'] = package_info['python_version']
            package_node['packagetype'] = package_info['packagetype']
            # Push the updated node to the graph
            graph.push(package_node)

if __name__ == '__main__':
    # Iterate over all data sources and their JSON files
    count = 0
    package_manager_dict = defaultdict(list)
    base_dir = '/Users/blue/Documents/GitHub/IntelliGraph/Dataset/IntelliJson'
    for source_dir in os.listdir(base_dir):
        source_path = os.path.join(base_dir, source_dir)
        if os.path.isdir(source_path):
            for json_file in os.listdir(source_path):
                if json_file.endswith('_verify_gpt4.json'):
                    json_file_stamp = json_file.replace('_verify_gpt4.json', '')
                    postdate = extract_timestamp(json_file_stamp)
                    json_file_path = os.path.join(source_path, json_file)
                    if os.stat(json_file_path).st_size == 0:
                        print(f"Warning: {json_file_path} is empty.")
                        continue
                    try:
                        with open(json_file_path, 'r') as f:
                            data = json.load(f)
                        package_names_list = []
                        find_and_extract_package_names(data, package_names_list)
                        for package_data in package_names_list:
                            create_package_graph(package_data, source_dir, postdate)
                            package_name = package_data.get('package_name', [])
                            package_manager = package_data.get('package_manager', [])
                            # 将 package_name 和 package_manager 处理为列表
                            if isinstance(package_name, str):
                                package_name = [package_name.lower()]
                            else:
                                package_name = [name.lower() for name in package_name]
                            if isinstance(package_manager, str):
                                package_manager = [package_manager.lower()]
                            else:
                                package_manager = list(set(manager.lower() for manager in package_manager))
                            # 生成字典键并整理数据
                            if len(package_manager) == 1:
                                key = package_manager[0]
                            else:
                                key = '-'.join(package_manager)
                            package_manager_dict[key].extend(package_name)
                    except Exception as e:
                        print(f"Error processing {json_file}: {e}")
    # 对每个 key 的包列表去重
    for key in package_manager_dict:
        package_manager_dict[key] = list(set(package_manager_dict[key]))
    # 统计每一个 key 有多少个包
    for key, packages in package_manager_dict.items():
        print(f"Package Manager: {key}, Number of Packages: {len(packages)}")
    update_graph_with_basic_info(package_manager_dict)
    # The graph is now built and ready to be visualized using Neo4j.
    print("Knowledge graph has been successfully created in Neo4j.")