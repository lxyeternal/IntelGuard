#!/usr/bin/env python3
"""
恶意包检测运行脚本

用法示例：
    # 检测PyPI包
    python run_detection.py /path/to/pypi_package pypi
    
    # 检测npm包
    python run_detection.py /path/to/npm_package npm
"""

import sys
from pathlib import Path

# 添加项目根目录到路径
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
    """主函数"""
    
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
    
    # 验证包管理器
    if package_manager not in ["npm", "pypi"]:
        print(f"❌ 错误: 不支持的包管理器 '{package_manager}'")
        print("   支持的包管理器: npm, pypi")
        sys.exit(1)
    
    # 验证路径
    if not Path(package_path).exists():
        print(f"❌ 错误: 路径不存在: {package_path}")
        sys.exit(1)
    
    # 设置输出路径
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
        # 初始化检测器
        logger.info("正在初始化检测器...")
        detector = PackageMalwareDetector(
            malice_threshold=0.5  # 使用默认知识库路径
        )
        
        # 执行检测
        logger.info("开始执行检测...")
        result = detector.detect_package(
            package_path=package_path,
            package_manager=package_manager,
            output_json=str(output_path)
        )
        
        # 显示最终结果
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

