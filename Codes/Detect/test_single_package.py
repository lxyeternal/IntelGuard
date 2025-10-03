#!/usr/bin/env python3
"""
快速测试单个包的检测脚本
使用方法：
    python test_single_package.py
"""

import os
import sys
import json
from pathlib import Path
from package_detector import PackageMalwareDetector

def test_package():
    """测试单个包"""
    
    # 你的测试包路径
    package_path = "/Users/blue/Documents/Github/IntelliGraph/Dataset/Packages/4123-1-py3-none-any"
    
    # 检查路径是否存在
    if not os.path.exists(package_path):
        print(f"❌ 错误：路径不存在: {package_path}")
        return
    
    print("=" * 80)
    print("🔍 恶意包检测测试")
    print("=" * 80)
    print(f"📦 测试包路径: {package_path}")
    print(f"📦 包名称: {Path(package_path).name}")
    print("-" * 80)
    
    # 输出路径
    output_path = f"Results/test_{Path(package_path).name}_report.json"
    
    try:
        # 初始化检测器
        print("\n📚 正在初始化检测器...")
        detector = PackageMalwareDetector(
            kb_path="./rag_kb_quick",    # 使用快速知识库路径
            malice_threshold=0.5         # 恶意判定阈值
        )
        
        # 执行检测
        print("\n🚀 开始检测...")
        result = detector.detect_package(
            package_path=package_path,
            output_json=output_path
        )
        
        # 显示结果摘要
        print("\n" + "=" * 80)
        print("📊 检测结果摘要")
        print("=" * 80)
        print(f"包名称: {result.package_name}")
        print(f"检测时间: {result.detection_time}")
        print(f"总耗时: {result.total_elapsed_time:.2f}秒")
        print()
        print(f"扫描文件数: {result.total_files_scanned}")
        print(f"总切片数: {result.total_slices}")
        print(f"恶意切片数: {result.malicious_slices_count}")
        print()
        
        if result.is_malicious_package:
            print("⚠️  判定结果: 🚨 恶意包")
            print(f"   恶意概率: {result.overall_malice_score:.2%}")
            print(f"   置信度: {result.overall_confidence:.2%}")
        else:
            print("✅ 判定结果: ✓ 良性包")
            print(f"   恶意概率: {result.overall_malice_score:.2%}")
        
        print()
        print("-" * 80)
        print(f"📄 完整报告已保存到: {output_path}")
        print("=" * 80)
        
        # 显示恶意切片详情（如果有）
        if result.malicious_slices_count > 0:
            print("\n🔎 恶意切片详情:")
            print("-" * 80)
            for i, slice_result in enumerate(result.slice_results[:5], 1):  # 只显示前5个
                if slice_result['is_malicious']:
                    print(f"\n切片 #{i}:")
                    print(f"  文件: {slice_result['file_path']}")
                    print(f"  行为: {slice_result['behavior_summary'][:100]}...")
                    print(f"  恶意分数: {slice_result['malice_score']:.2f}")
                    print(f"  解释: {slice_result['explanation'][:150]}...")
            
            if result.malicious_slices_count > 5:
                print(f"\n... 还有 {result.malicious_slices_count - 5} 个恶意切片，详见完整报告")
        
        print("\n" + "=" * 80)
        print("✅ 测试完成！")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ 检测过程出错: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_package()

