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
from py2neo import Graph, Node, Relationship


# Connect to Neo4j (assuming it's running locally with default settings)
graph = Graph("bolt://localhost:7687", auth=("neo4j", "12345678"), name="intelligraph")
# Clear the existing graph
graph.delete_all()


# Helper function to create or merge nodes and relationships based on your specified entities
def create_package_graph(package_data, source_name):
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


if __name__ == '__main__':
    # Iterate over all data sources and their JSON files
    base_dir = '/Users/blue/Documents/GitHub/IntelliGraph/Dataset/IntelliJson'
    for source_dir in os.listdir(base_dir):
        source_path = os.path.join(base_dir, source_dir)
        if os.path.isdir(source_path):
            for json_file in os.listdir(source_path):
                if json_file.endswith('_verify_gpt4.json'):
                    json_file_path = os.path.join(source_path, json_file)
                    # Load the JSON data
                    try:
                        with open(json_file_path, 'r') as f:
                            data = json.load(f)
                        # Process each package in the "packages" list
                        for package in data.get('packages', []):
                            create_package_graph(package, source_dir)
                    except Exception as e:
                        pass
    # The graph is now built and ready to be visualized using Neo4j.
    print("Knowledge graph has been successfully created in Neo4j.")
