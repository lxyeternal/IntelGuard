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

current_dir = os.path.dirname(os.path.abspath(__file__))
codes_dir = os.path.dirname(current_dir)
project_dir = os.path.dirname(codes_dir)

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
    for package_name in package_names:
        if not package_name:
            print(f"Skipping entry with missing package_name from source: {source_name}")
            continue

        # Convert package_name to lowercase
        package_name = package_name.lower()
        # Merge package node (to avoid duplication)
        package_node = Node("Package", name=package_name)
        graph.merge(package_node, "Package", "name")
        # Convert source_name to lowercase
        source_name = source_name.lower()
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
            if isinstance(package_data['package_manager'], list):
                pm_name = ', '.join(sorted([pm.lower() for pm in package_data['package_manager']]))
            else:
                pm_name = package_data['package_manager'].lower()
            pm_node = Node("PackageManager", name=pm_name)
            graph.merge(pm_node, "PackageManager", "name")
            rel = Relationship(package_node, "HOSTED_ON", pm_node)
            graph.merge(rel)

        if 'affected_platform' in package_data:
            if isinstance(package_data['affected_platform'], list):
                platforms = [platform.lower() for platform in package_data['affected_platform']]
            else:
                platforms = [package_data['affected_platform'].lower()]
            for platform in platforms:
                platform = platform.lower()
                platform_node = Node("Platform", name=platform)
                graph.merge(platform_node, "Platform", "name")
                rel = Relationship(package_node, "AFFECTS_PLATFORM", platform_node)
                graph.merge(rel)

        if 'publisher_name' in package_data:
            if isinstance(package_data['publisher_name'], list):
                publisher_name = ', '.join(sorted([pub.lower() for pub in package_data['publisher_name']]))
            else:
                publisher_name = package_data['publisher_name'].lower()
            publisher_node = Node("Publisher", name=publisher_name)
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
    ollected_pagelinks_path = os.path.join(codes_dir, "Collection", "pagelinks", "collected_pagelinks.txt")
    with open(ollected_pagelinks_path, 'r') as file:
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
    """
    将新结构的 pypi_basic_info 数据更新到图中
    数据结构:
    package_name -> {
        description, author, author_email,
        versions: {
            version_name -> {
                uploaded_via, upload_time, size, python_version, packagetype
            }
        }
    }
    """
    pypi_basic_info = process_package_data(package_manager_dict)
    print(pypi_basic_info)

    # Save pypi_basic_info to JSON file
    pypi_basic_info_path = os.path.join(project_dir, "pypi_basic_info.json")
    with open(pypi_basic_info_path, 'w') as json_file:
        json.dump(pypi_basic_info, json_file, indent=4)

    for package_name, package_info in pypi_basic_info.items():
        try:
            # 1. 获取或创建 Package 节点
            package_node = graph.nodes.match("Package", name=package_name).first()
            if not package_node:
                package_node = Node("Package", name=package_name)
                graph.create(package_node)

            # 2. 处理包级别的属性（description, author, author_email）
            # 2.1 处理 description
            if package_info['description'] is not None:
                desc_node = graph.nodes.match("Description", content=package_info['description']).first()
                if not desc_node:
                    desc_node = Node("Description", content=package_info['description'])
                    graph.create(desc_node)

                has_desc = graph.match_one((package_node, desc_node), "HAS_DESCRIPTION")
                if not has_desc:
                    has_desc = Relationship(package_node, "HAS_DESCRIPTION", desc_node)
                    graph.create(has_desc)

            # 2.2 处理 author
            if package_info['author'] is not None:
                author_node = graph.nodes.match("Author", name=package_info['author']).first()
                if not author_node:
                    author_node = Node("Author", name=package_info['author'])
                    graph.create(author_node)

                authored_by = graph.match_one((package_node, author_node), "AUTHORED_BY")
                if not authored_by:
                    authored_by = Relationship(package_node, "AUTHORED_BY", author_node)
                    graph.create(authored_by)

            # 2.3 处理 author_email
            if package_info['author_email'] is not None:
                email_node = graph.nodes.match("AuthorEmail", email=package_info['author_email']).first()
                if not email_node:
                    email_node = Node("AuthorEmail", email=package_info['author_email'])
                    graph.create(email_node)

                has_email = graph.match_one((package_node, email_node), "HAS_EMAIL")
                if not has_email:
                    has_email = Relationship(package_node, "HAS_EMAIL", email_node)
                    graph.create(has_email)

            # 3. 处理版本及其相关属性
            for version_name, version_info in package_info['versions'].items():
                # 3.1 创建或获取 Version 节点
                version_node = graph.nodes.match("Version", name=version_name).first()
                if not version_node:
                    version_node = Node("Version", name=version_name)
                    graph.create(version_node)

                # 创建 Package -> Version 关系
                has_version = graph.match_one((package_node, version_node), "HAS_VERSION")
                if not has_version:
                    has_version = Relationship(package_node, "HAS_VERSION", version_node)
                    graph.create(has_version)

                # 3.2 处理 uploaded_via
                if version_info['uploaded_via']:
                    for uploader in version_info['uploaded_via']:
                        uploader_node = graph.nodes.match("UploadedVia", name=uploader).first()
                        if not uploader_node:
                            uploader_node = Node("UploadedVia", name=uploader)
                            graph.create(uploader_node)

                        uploaded_via = graph.match_one((version_node, uploader_node), "UPLOADED_VIA")
                        if not uploaded_via:
                            uploaded_via = Relationship(version_node, "UPLOADED_VIA", uploader_node)
                            graph.create(uploaded_via)

                # 3.3 处理 upload_time
                if version_info['upload_time']:
                    for upload_time in version_info['upload_time']:
                        time_node = graph.nodes.match("UploadTime", date=upload_time).first()
                        if not time_node:
                            time_node = Node("UploadTime", date=upload_time)
                            graph.create(time_node)

                        uploaded_at = graph.match_one((version_node, time_node), "UPLOADED_AT")
                        if not uploaded_at:
                            uploaded_at = Relationship(version_node, "UPLOADED_AT", time_node)
                            graph.create(uploaded_at)

                # 3.4 处理 size
                if version_info['size']:
                    for size_value in version_info['size']:
                        size_node = graph.nodes.match("Size", value=size_value).first()
                        if not size_node:
                            size_node = Node("Size", value=size_value)
                            graph.create(size_node)

                        has_size = graph.match_one((version_node, size_node), "HAS_SIZE")
                        if not has_size:
                            has_size = Relationship(version_node, "HAS_SIZE", size_node)
                            graph.create(has_size)

                # 3.5 处理 python_version
                if version_info['python_version']:
                    for py_version in version_info['python_version']:
                        py_version_node = graph.nodes.match("PythonVersion", name=py_version).first()
                        if not py_version_node:
                            py_version_node = Node("PythonVersion", name=py_version)
                            graph.create(py_version_node)

                        supports_python = graph.match_one((version_node, py_version_node), "SUPPORTS_PYTHON")
                        if not supports_python:
                            supports_python = Relationship(version_node, "SUPPORTS_PYTHON", py_version_node)
                            graph.create(supports_python)

                # 3.6 处理 packagetype
                if version_info['packagetype']:
                    for pkg_type in version_info['packagetype']:
                        type_node = graph.nodes.match("PackageType", name=pkg_type).first()
                        if not type_node:
                            type_node = Node("PackageType", name=pkg_type)
                            graph.create(type_node)

                        has_type = graph.match_one((version_node, type_node), "HAS_TYPE")
                        if not has_type:
                            has_type = Relationship(version_node, "HAS_TYPE", type_node)
                            graph.create(has_type)

            # 提交更新
            graph.push(package_node)
            print(f"成功更新包 {package_name} 的信息")

        except Exception as e:
            print(f"处理包 {package_name} 时出错: {str(e)}")
            continue

    print("所有包信息更新完成")


if __name__ == '__main__':
    # Iterate over all data sources and their JSON files
    count = 0
    package_manager_dict = defaultdict(list)
    base_dir = os.path.join(project_dir, "Dataset", "IntelliJson")
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
    # Save package_manager_dict to JSON file
    output_json_path = os.path.join(project_dir, "package_manager_dict.json")
    # with open(output_json_path, 'w') as json_file:
    #     json.dump(package_manager_dict, json_file, indent=4)
    # Load package_manager_dict from JSON file
    with open(output_json_path, 'r') as json_file:
        loaded_package_manager_dict = json.load(json_file)
    update_graph_with_basic_info(loaded_package_manager_dict)
    # The graph is now built and ready to be visualized using Neo4j.
    print("Knowledge graph has been successfully created in Neo4j.")