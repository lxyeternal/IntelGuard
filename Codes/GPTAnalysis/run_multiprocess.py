#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : run_multiprocess.py
# @Project  : IntelliGraph
# Time      : 2025/10/01
# Author    : honywen
# version   : python 3.8
# Description: Convenient script to run multi-process IntelliLLM analysis
"""

from multiprocessing import cpu_count
from intellgpt_multiprocess import IntelliLLMMultiProcess


# ============ 配置区域 ============
# 在这里直接修改要处理的 sources 和进程数

# 要处理的 sources（可以是单个或多个）
SOURCES_TO_PROCESS = [
    # "bleepingcomputer",
    # "sonatype", 
    # "checkmarx",
    # "medium",
    # "qianxin",
    # "datadoghq",
    # "snyk",
    "phylum",
    "jfrog",
    "fortinet",
    "rhisac",
    "socket",
    "securityaffairs",
    "securityweek",
    "reversinglabs",
    "cybersecuritynews",
    "checkpoint"
]

# 进程数配置
# 选项1: 使用具体数字，例如 4
# 选项2: 使用 cpu_count() 表示使用所有 CPU 核心
# 选项3: 使用 cpu_count() // 2 表示使用一半 CPU 核心（推荐）
NUM_PROCESSES = 20

# ============ 配置区域结束 ============


def main():
    print(f"Processing {len(SOURCES_TO_PROCESS)} source(s): {', '.join(SOURCES_TO_PROCESS)}")
    print(f"Using {NUM_PROCESSES} processes (CPU count: {cpu_count()})")
    print("=" * 60)
    
    # 创建多进程实例并开始处理
    mp_gpt = IntelliLLMMultiProcess(num_processes=NUM_PROCESSES)
    mp_gpt.start(SOURCES_TO_PROCESS)
    
    print("=" * 60)
    print("All processing completed!")


if __name__ == '__main__':
    main()

