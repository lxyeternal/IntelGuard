#!/usr/bin/env python3
"""
知识库结构查看器

用途：查看知识库的Schema结构，并展示实例数据
使用方法：
    python view_knowledge_base.py
    或指定知识库路径：
    python view_knowledge_base.py --kb-path ./KnowledgeBase
"""

import json
import sys
from pathlib import Path
import numpy as np
import argparse


def print_section(title: str, char: str = "="):
    """打印分隔符"""
    print(f"\n{char * 80}")
    print(f"{title}")
    print(f"{char * 80}")


def format_json(data, indent=2):
    """格式化JSON并截断长字符串"""
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if isinstance(v, str) and len(v) > 200:
                result[k] = v[:200] + "... (截断)"
            elif isinstance(v, list) and len(v) > 3:
                result[k] = v[:3] + [f"... 还有 {len(v) - 3} 项"]
            else:
                result[k] = v
        return json.dumps(result, indent=indent, ensure_ascii=False)
    return json.dumps(data, indent=indent, ensure_ascii=False)


def view_knowledge_base(kb_path: str):
    """查看知识库结构和内容"""
    
    kb_path = Path(kb_path)
    
    print_section("🔍 知识库结构查看器")
    print(f"📂 知识库路径: {kb_path}")
    
    # 检查路径是否存在
    if not kb_path.exists():
        print(f"\n❌ 错误：知识库路径不存在: {kb_path}")
        print("\n💡 提示：请先运行 build_knowledge_base.py 构建知识库")
        return
    
    # 列出知识库中的文件
    print_section("📁 知识库文件列表", "-")
    kb_files = list(kb_path.iterdir())
    if not kb_files:
        print("  (空目录)")
        return
    
    for f in sorted(kb_files):
        size = f.stat().st_size if f.is_file() else 0
        size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/(1024*1024):.2f} MB"
        file_type = "📄" if f.is_file() else "📁"
        print(f"  {file_type} {f.name:<30} {size_str:>15}")
    
    # 1. 读取知识库JSON
    kb_json_path = kb_path / "knowledge_base.json"
    if not kb_json_path.exists():
        print(f"\n❌ 未找到 knowledge_base.json")
        return
    
    print_section("📊 知识库JSON结构")
    
    with open(kb_json_path, 'r', encoding='utf-8') as f:
        kb_data = json.load(f)
    
    # 显示顶层结构
    print("\n🔸 顶层字段:")
    for key in kb_data.keys():
        value = kb_data[key]
        if isinstance(value, list):
            print(f"  - {key}: List[{len(value)}]")
        elif isinstance(value, dict):
            print(f"  - {key}: Dict with {len(value)} keys")
        else:
            print(f"  - {key}: {type(value).__name__}")
    
    # 动态分析知识库结构
    if 'packages' in kb_data and len(kb_data['packages']) > 0:
        print_section("🔸 packages 结构（单个包的Schema）", "-")
        
        package_example = kb_data['packages'][0]
        
        print("\n包级别字段:")
        for key, value in package_example.items():
            value_type = type(value).__name__
            value_preview = ""
            
            if isinstance(value, str):
                value_preview = f" = '{value[:50]}...'" if len(value) > 50 else f" = '{value}'"
            elif isinstance(value, (int, float, bool)):
                value_preview = f" = {value}"
            elif isinstance(value, list):
                value_preview = f" (长度: {len(value)})"
                if len(value) > 0 and key == 'malicious_snippets':
                    # 显示snippet的结构
                    print(f"  - {key:<25} : {value_type:<12} {value_preview}")
                    snippet = value[0]
                    print(f"\n    每个snippet包含的字段:")
                    for skey, svalue in snippet.items():
                        stype = type(svalue).__name__
                        spreview = ""
                        if isinstance(svalue, str):
                            spreview = f" = '{svalue[:40]}...'" if len(svalue) > 40 else f" = '{svalue}'"
                        elif isinstance(svalue, (int, float, bool)):
                            spreview = f" = {svalue}"
                        elif isinstance(svalue, list):
                            spreview = f" (长度: {len(svalue)})"
                        elif isinstance(svalue, dict):
                            spreview = f" (包含 {len(svalue)} 个字段)"
                        print(f"      • {skey:<23} : {stype:<12} {spreview}")
                    continue
            elif isinstance(value, dict):
                value_preview = f" (包含 {len(value)} 个字段)"
            
            print(f"  - {key:<25} : {value_type:<12} {value_preview}")
        
        # 显示完整的第一个包示例
        print_section("📝 完整示例（第1个包）", "-")
        print(format_json(package_example))
        
        # 统计信息
        print_section("📈 知识库统计信息", "-")
        metadata = kb_data.get('metadata', {})
        print(f"  总包数: {metadata.get('total_packages', len(kb_data['packages']))}")
        print(f"  总片段数: {metadata.get('total_snippets', 'N/A')}")
        
        # 统计每个包的snippet数量
        snippet_counts = [len(pkg.get('malicious_snippets', [])) for pkg in kb_data['packages']]
        if snippet_counts:
            avg_snippets = sum(snippet_counts) / len(snippet_counts)
            max_snippets = max(snippet_counts)
            min_snippets = min(snippet_counts)
            print(f"  每个包的平均片段数: {avg_snippets:.1f}")
            print(f"  最多片段数: {max_snippets}")
            print(f"  最少片段数: {min_snippets}")
        
        # 显示前10个包
        print(f"\n  包列表（前10个）:")
        for i, pkg in enumerate(kb_data['packages'][:10], 1):
            pkg_name = pkg.get('package_info', {}).get('name', 'Unknown')
            snippet_count = len(pkg.get('malicious_snippets', []))
            kb_id = pkg.get('kb_id', 'N/A')
            print(f"    {i}. {pkg_name:<40} ({snippet_count} 片段) [ID: {kb_id}]")
        if len(kb_data['packages']) > 10:
            print(f"    ... 还有 {len(kb_data['packages']) - 10} 个包")
    
    elif 'knowledge_entries' in kb_data and len(kb_data['knowledge_entries']) > 0:
        print_section("🔸 knowledge_entries 结构（单条数据的Schema）", "-")
        
        entry_example = kb_data['knowledge_entries'][0]
        
        print("\n字段说明:")
        for key, value in entry_example.items():
            value_type = type(value).__name__
            value_preview = ""
            
            if isinstance(value, str):
                value_preview = f" = '{value[:50]}...'" if len(value) > 50 else f" = '{value}'"
            elif isinstance(value, (int, float, bool)):
                value_preview = f" = {value}"
            elif isinstance(value, list):
                value_preview = f" (长度: {len(value)})"
            elif isinstance(value, dict):
                value_preview = f" (包含 {len(value)} 个字段)"
            
            print(f"  - {key:<25} : {value_type:<12} {value_preview}")
        
        # 显示完整的第一条示例
        print_section("📝 完整示例（第1条知识条目）", "-")
        print(format_json(entry_example))
        
        # 统计信息
        print_section("📈 知识库统计信息", "-")
        print(f"  总条目数: {len(kb_data['knowledge_entries'])}")
        
        # 统计包名分布
        package_names = [entry.get('package_name', 'Unknown') for entry in kb_data['knowledge_entries']]
        unique_packages = set(package_names)
        print(f"  唯一包数量: {len(unique_packages)}")
        
        # 统计code_snippet长度
        snippet_lengths = [len(entry.get('code_snippet', '')) for entry in kb_data['knowledge_entries']]
        avg_snippet_len = sum(snippet_lengths) / len(snippet_lengths) if snippet_lengths else 0
        print(f"  平均代码片段长度: {avg_snippet_len:.0f} 字符")
        
        # 统计malice_score分布
        malice_scores = [entry.get('malice_score', 0) for entry in kb_data['knowledge_entries']]
        avg_malice = sum(malice_scores) / len(malice_scores) if malice_scores else 0
        print(f"  平均恶意分数: {avg_malice:.2f}")
        
        # 显示前10个包
        print(f"\n  包含的包（前10个）:")
        for i, pkg in enumerate(sorted(unique_packages)[:10], 1):
            count = package_names.count(pkg)
            print(f"    {i}. {pkg:<40} ({count} 条)")
        if len(unique_packages) > 10:
            print(f"    ... 还有 {len(unique_packages) - 10} 个包")
    
    # 2. 读取embeddings（动态查找所有.npy文件）
    print_section("🧮 Embeddings 文件", "-")
    
    npy_files = list(kb_path.glob("*.npy"))
    if npy_files:
        for npy_file in sorted(npy_files):
            print(f"\n📊 {npy_file.name}:")
            emb = np.load(npy_file)
            print(f"  形状: {emb.shape}")
            print(f"  数据类型: {emb.dtype}")
            if len(emb.shape) == 2:
                print(f"  维度: {emb.shape[1]} 维向量")
                print(f"  向量数量: {emb.shape[0]}")
                print(f"  第一个向量（前10个元素）:")
                print(f"    {emb[0][:10]}")
            else:
                print(f"  数据维度: {len(emb.shape)}D")
    else:
        print("  未找到 .npy 文件")
    
    # 3. 动态生成完整Schema说明
    print_section("📋 实际知识库结构总结")
    
    print("\n知识库文件组成:")
    all_files = sorted(kb_path.iterdir())
    for i, f in enumerate(all_files, 1):
        if f.is_file():
            print(f"  {i}. {f.name}")
    
    print("\nknowledge_base.json 结构:")
    for key, value in kb_data.items():
        if isinstance(value, list):
            print(f"  ├── {key}: List[{len(value)}]")
            if len(value) > 0 and isinstance(value[0], dict):
                print(f"  │   └── 每个条目包含字段: {', '.join(list(value[0].keys())[:5])}...")
        elif isinstance(value, dict):
            print(f"  ├── {key}: Dict")
            for subkey in list(value.keys())[:3]:
                print(f"  │   ├── {subkey}")
            if len(value) > 3:
                print(f"  │   └── ... 还有 {len(value) - 3} 个字段")
    
    if npy_files:
        print(f"\nEmbedding 文件:")
        for npy_file in sorted(npy_files):
            emb = np.load(npy_file)
            if len(emb.shape) == 2:
                print(f"  ├── {npy_file.name}: ({emb.shape[0]} 向量 × {emb.shape[1]} 维度)")
            else:
                print(f"  ├── {npy_file.name}: {emb.shape}")
    
    print("\n使用建议:")
    print("  1. 加载 knowledge_base.json 获取恶意包/代码片段元数据")
    print("  2. 加载对应的 .npy 文件获取向量表示")
    print("  3. 使用向量相似度检索相关恶意模式")
    print("  4. 结合元数据和检索结果进行恶意包检测")
    
    print_section("✅ 查看完成", "=")
    print(f"💡 知识库包含 {len(kb_data.get('packages', kb_data.get('knowledge_entries', [])))} 个条目")
    if 'metadata' in kb_data:
        meta = kb_data['metadata']
        if 'total_snippets' in meta:
            print(f"   共 {meta['total_snippets']} 个恶意代码片段")
    print()


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='查看知识库结构')
    parser.add_argument(
        '--kb-path',
        type=str,
        default='./KnowledgeBase',
        help='知识库路径 (默认: ./KnowledgeBase)'
    )
    
    args = parser.parse_args()
    view_knowledge_base(args.kb_path)


if __name__ == "__main__":
    main()

