# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : test.py
# @Project  : IntelliGraph
# Time      : 27/8/24 4:19 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""


import json
from py2neo import Graph, Node, Relationship

# Connect to Neo4j (assuming it's running locally with default settings)
graph = Graph("bolt://localhost:7687", auth=("neo4j", "12345678"), name="intelligraph")

# Clear the existing graph
graph.delete_all()

# Load data from the provided JSON files
with open('/Users/blue/Documents/GitHub/IntelliGraph/Dataset/CodeJson/aiogram-types/0.1.8/entity_gpt4.json', 'r') as f:
    entity_data = json.load(f)

with open('/Users/blue/Documents/GitHub/IntelliGraph/Dataset/IntelliJson/case/thehackernews_case_verify_gpt4.json', 'r') as f:
    hackernews_data = json.load(f)

with open('/Users/blue/Documents/GitHub/IntelliGraph/Dataset/IntelliJson/case/secrss_case_verify_gpt4.json', 'r') as f:
    secrss_data = json.load(f)

with open('/Users/blue/Documents/GitHub/IntelliGraph/Dataset/IntelliJson/case/checkmarx_case_verify_gpt4.json', 'r') as f:
    checkmarx_data = json.load(f)

# Helper function to create nodes and relationships
def create_package_graph(data):
    for package in data.get('package_name', []):
        package_node = Node("Package", name=package)
        graph.merge(package_node, "Package", "name")

        if 'functionality' in data:
            for func in data['functionality']:
                func_node = Node("Functionality", description=func)
                graph.merge(func_node, "Functionality", "description")
                rel = Relationship(package_node, "HAS_FUNCTIONALITY", func_node)
                graph.merge(rel)

        if 'behavior' in data:
            for behavior in data['behavior']:
                behavior_node = Node("Behavior", description=behavior)
                graph.merge(behavior_node, "Behavior", "description")
                rel = Relationship(package_node, "HAS_BEHAVIOR", behavior_node)
                graph.merge(rel)

        if 'impact' in data:
            for impact in data['impact']:
                impact_node = Node("Impact", description=impact)
                graph.merge(impact_node, "Impact", "description")
                rel = Relationship(package_node, "HAS_IMPACT", impact_node)
                graph.merge(rel)

        if 'mitigation_measures' in data:
            for measure in data['mitigation_measures']:
                measure_node = Node("Mitigation", description=measure)
                graph.merge(measure_node, "Mitigation", "description")
                rel = Relationship(package_node, "HAS_MITIGATION", measure_node)
                graph.merge(rel)

        if 'IOC' in data:
            for ioc in data['IOC']:
                ioc_node = Node("IOC", indicator=ioc)
                graph.merge(ioc_node, "IOC", "indicator")
                rel = Relationship(package_node, "HAS_IOC", ioc_node)
                graph.merge(rel)

# Create graph nodes and relationships from all data sources
create_package_graph(hackernews_data)
create_package_graph(secrss_data)
create_package_graph(checkmarx_data)

# Handling entity_data (which has a different structure)
package_node = Node("Package", name=entity_data['package_name'])
graph.merge(package_node, "Package", "name")

for file_data in entity_data['files']:
    file_node = Node("File", name=file_data['file_name'], hash=file_data['hash'])
    graph.merge(file_node, "File", "name")
    rel = Relationship(package_node, "CONTAINS_FILE", file_node)
    graph.merge(rel)

    for snippet in file_data['code_snippets']:
        code_node = Node("CodeSnippet", code=snippet['code'], lines=snippet['lines'])
        graph.merge(code_node, "CodeSnippet", "code")
        rel = Relationship(file_node, "CONTAINS_SNIPPET", code_node)
        graph.merge(rel)

        for api_call in snippet['api_calls']:
            api_node = Node("APICall", name=api_call['api_name'], description=api_call['description'])
            graph.merge(api_node, "APICall", "name")
            rel = Relationship(code_node, "USES_API", api_node)
            graph.merge(rel)

        for behavior in snippet['malicious_behaviors']:
            behavior_node = Node("Behavior", description=behavior['behavior_type'])
            graph.merge(behavior_node, "Behavior", "description")
            rel = Relationship(code_node, "TRIGGERS_BEHAVIOR", behavior_node)
            graph.merge(rel)

for dependency in entity_data['dependencies']:
    dep_node = Node("Dependency", name=dependency['package_name'], version=dependency['version'])
    graph.merge(dep_node, "Dependency", "name")
    rel = Relationship(package_node, "USES_DEPENDENCY", dep_node)
    graph.merge(rel)

for resource in entity_data['external_resources']:
    resource_node = Node("Resource", type=resource['resource_type'], value=resource['resource_value'])
    graph.merge(resource_node, "Resource", "value")
    rel = Relationship(package_node, "HAS_RESOURCE", resource_node)
    graph.merge(rel)

# The graph is now built and ready to be visualized using Neo4j.
print("Knowledge graph has been successfully created in Neo4j.")
