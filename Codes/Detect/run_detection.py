#!/usr/bin/env python3
"""Detect one package from the command line."""

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.Detect.package_detector import PackageMalwareDetector
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Command line entry point."""
    
    if len(sys.argv) < 3:
        print("用法: python run_detection.py <包路径> <包管理器>")
        print("包管理器: npm 或 pypi")
        print()
        print("示例:")
        print("  python run_detection.py /path/to/package pypi")
        print("  python run_detection.py /path/to/package npm")
        sys.exit(1)
    
    package_path = sys.argv[1]
    package_manager = sys.argv[2].lower()
    
    if package_manager not in ["npm", "pypi"]:
        print(f"❌ 错误: 不支持的包管理器 '{package_manager}'")
        print("   支持的包管理器: npm, pypi")
        sys.exit(1)
    
    if not Path(package_path).exists():
        print(f"❌ 错误: 路径不存在: {package_path}")
        sys.exit(1)
    
    package_name = Path(package_path).name
    output_path = project_root / "Results" / "malware_detection" / f"{package_name}_report.json"
    
    print("\n" + "="*80)
    print("🔍 恶意包检测系统")
    print("="*80)
    print(f"📦 包路径: {package_path}")
    print(f"📦 包名称: {package_name}")
    print(f"🏷️  包管理器: {package_manager.upper()}")
    print(f"📄 输出文件: {output_path}")
    print("="*80 + "\n")
    
    try:
        logger.info("正在初始化检测器...")
        detector = PackageMalwareDetector()
        
        logger.info("开始执行检测...")
        result = detector.detect_package(
            package_path=package_path,
            package_manager=package_manager,
            output_json=str(output_path)
        )
        
        print("\n" + "="*80)
        print("✅ 检测完成！")
        print("="*80)
        
        if result.is_malicious_package:
            print("🔴 判定结果: 恶意包")
            exit_code = 1
        else:
            print("🟢 判定结果: 正常包")
            exit_code = 0
        
        print(f"\n📊 详细报告已保存到: {output_path}")
        print("="*80 + "\n")
        
        return exit_code
        
    except Exception as e:
        logger.error(f"检测过程出错: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

