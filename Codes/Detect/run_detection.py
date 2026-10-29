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
        print("Usage: python run_detection.py <package_path> <package_manager>")
        print("package_manager: npm or pypi")
        print()
        print("Examples:")
        print("  python run_detection.py /path/to/package pypi")
        print("  python run_detection.py /path/to/package npm")
        sys.exit(1)
    
    package_path = sys.argv[1]
    package_manager = sys.argv[2].lower()
    
    if package_manager not in ["npm", "pypi"]:
        print(f"❌ Error: unsupported package manager '{package_manager}'")
        print("   Supported: npm, pypi")
        sys.exit(1)
    
    if not Path(package_path).exists():
        print(f"❌ Error: path not found: {package_path}")
        sys.exit(1)
    
    package_name = Path(package_path).name
    output_path = project_root / "Results" / "malware_detection" / f"{package_name}_report.json"
    
    print("\n" + "="*80)
    print("🔍 Malicious package detection")
    print("="*80)
    print(f"📦 Package path: {package_path}")
    print(f"📦 Package name: {package_name}")
    print(f"🏷️  Package manager: {package_manager.upper()}")
    print(f"📄 Output file: {output_path}")
    print("="*80 + "\n")
    
    try:
        logger.info("Initializing the detector...")
        detector = PackageMalwareDetector()
        
        logger.info("Running detection...")
        result = detector.detect_package(
            package_path=package_path,
            package_manager=package_manager,
            output_json=str(output_path)
        )
        
        print("\n" + "="*80)
        print("✅ Detection finished")
        print("="*80)
        
        if result.is_malicious_package:
            print("🔴 Verdict: malicious")
            exit_code = 1
        else:
            print("🟢 Verdict: benign")
            exit_code = 0
        
        print(f"\n📊 Report written to: {output_path}")
        print("="*80 + "\n")
        
        return exit_code
        
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

