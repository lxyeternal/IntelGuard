"""
端到端恶意包检测系统

功能流程：
1. 输入解压后的包路径和包管理器类型（npm/pypi）
2. 根据包管理器类型扫描相应文件：
   - pypi: 扫描所有.py文件
   - npm: 扫描package.json和所有.js文件
3. 对每个文件进行LLM代码切片
4. 对每个切片进行RAG恶意检测
5. 汇总结果并生成完整的检测报告JSON

只要有一个切片被判定为恶意，整个包就被标记为恶意包。
"""

import os
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
import logging

# 添加项目路径
project_root = str(Path(__file__).parent.parent.parent)  # IntelliGraph根目录
sys.path.insert(0, project_root)

from Codes.Detect.code_slice import LLMCodeSlicer
from Codes.KnowledgeBase.rag_detector import RAGMalwareDetector, RAGKnowledgeBase, DetectionResult
from Codes.GPTAnalysis.llmquery import LLMAgent

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class SliceDetectionResult:
    """单个切片的检测结果"""
    slice_id: str
    file_path: str
    code_snippet: str
    behavior_summary: str
    
    # RAG检测结果
    is_malicious: bool
    malice_score: float
    confidence: float
    explanation: str
    
    # 匹配的知识
    matched_knowledge: List[Dict[str, Any]]
    
    def to_dict(self):
        """转换为字典"""
        return {
            "slice_id": self.slice_id,
            "file_path": self.file_path,
            "code_snippet": self.code_snippet[:500] + "..." if len(self.code_snippet) > 500 else self.code_snippet,
            "behavior_summary": self.behavior_summary,
            "detection_result": {
                "is_malicious": self.is_malicious,
                "malice_score": round(self.malice_score, 4),
                "confidence": round(self.confidence, 4),
                "explanation": self.explanation
            },
            "top_matches": [
                {
                    # 基本匹配信息
                    "match_id": m["match_id"],
                    "source_package": m["source_package"],
                    "source_file": m["source_file"],
                    "match_type": m["match_type"],
                    
                    # 相似度分数
                    "similarity_score": round(m["similarity_score"], 4),
                    "code_similarity": round(m["code_similarity"], 4),
                    "behavior_similarity": round(m["behavior_similarity"], 4),
                    
                    # 完整的匹配片段（来自知识库）
                    "matched_snippet": m["matched_snippet"]
                }
                for m in self.matched_knowledge[:3]  # 只保留Top 3，但包含完整信息
            ]
        }


@dataclass  
class FileDetectionResult:
    """单个文件的检测结果"""
    file_path: str
    status: str  # "success", "error", "empty"
    total_slices: int
    malicious_slices: int
    is_malicious: bool  # 文件是否包含恶意代码
    
    slice_results: List[SliceDetectionResult]
    error: Optional[str] = None
    
    def to_dict(self):
        """转换为字典"""
        return {
            "file_path": self.file_path,
            "status": self.status,
            "summary": {
                "total_slices": self.total_slices,
                "malicious_slices": self.malicious_slices,
                "is_malicious": self.is_malicious,
                "malice_rate": round(self.malicious_slices / self.total_slices, 4) if self.total_slices > 0 else 0.0
            },
            "slice_detections": [s.to_dict() for s in self.slice_results],
            "error": self.error
        }


@dataclass
class PackageDetectionResult:
    """整个包的检测结果"""
    package_name: str
    package_path: str
    
    # 统计信息
    total_files: int
    processed_files: int
    total_slices: int
    malicious_slices: int
    
    # 包级判定
    is_malicious_package: bool  # 只要有一个切片恶意就为True
    
    # 详细结果
    file_results: List[FileDetectionResult]
    
    # 元数据
    detection_timestamp: str
    kb_info: Dict[str, Any]
    
    def to_dict(self):
        """转换为字典"""
        return {
            "package_info": {
                "package_name": self.package_name,
                "package_path": self.package_path,
                "detection_timestamp": self.detection_timestamp
            },
            "detection_summary": {
                "is_malicious_package": self.is_malicious_package,
                "verdict": "🔴 恶意包" if self.is_malicious_package else "🟢 正常包",
                "total_files_scanned": self.total_files,
                "successfully_processed": self.processed_files,
                "total_code_slices": self.total_slices,
                "malicious_slices_found": self.malicious_slices,
                "malice_rate": round(self.malicious_slices / self.total_slices, 4) if self.total_slices > 0 else 0.0
            },
            "knowledge_base_info": self.kb_info,
            "file_detections": [f.to_dict() for f in self.file_results]
        }


class PackageMalwareDetector:
    """端到端恶意包检测器（支持npm和pypi）"""
    
    def __init__(
        self, 
        kb_path: str = None,
        malice_threshold: float = 0.5,
        llm_agent: Optional[LLMAgent] = None
    ):
        """
        初始化检测器
        
        Args:
            kb_path: 知识库路径，默认为项目根目录下的KnowledgeBase
            malice_threshold: 恶意判定阈值
            llm_agent: LLM代理实例（可选）
        """
        if kb_path is None:
            # 默认使用项目根目录下的KnowledgeBase
            project_root = Path(__file__).parent.parent.parent
            kb_path = str(project_root / "KnowledgeBase")
        
        logger.info("初始化端到端恶意包检测器...")
        
        # 1. 初始化LLM代码切片器
        logger.info("[1/3] 初始化代码切片器...")
        self.slicer = LLMCodeSlicer(llm_agent=llm_agent)
        
        # 2. 初始化并加载RAG知识库
        logger.info("[2/3] 加载RAG知识库...")
        logger.info(f"   知识库路径: {kb_path}")
        self.kb = RAGKnowledgeBase(kb_path=kb_path)
        
        # 尝试加载已有知识库
        try:
            self.kb.load_kb()
            logger.info(f"   ✓ 已加载知识库: {len(self.kb.packages)} 个恶意包, {len(self.kb.snippet_index)} 个代码片段")
        except FileNotFoundError as e:
            logger.warning(f"   ⚠️  未找到知识库文件: {e}")
            logger.warning(f"   请先运行 Codes/KnowledgeBase/build_knowledge_base.py 构建知识库")
        except Exception as e:
            logger.error(f"   ❌ 加载知识库时发生错误: {e}")
            import traceback
            traceback.print_exc()
        
        # 3. 初始化RAG检测器
        logger.info("[3/3] 初始化RAG检测器...")
        self.detector = RAGMalwareDetector(knowledge_base=self.kb)
        self.malice_threshold = malice_threshold
        
        logger.info("✅ 检测器初始化完成！")
    
    def detect_package(
        self, 
        package_path: str, 
        package_manager: str = "pypi",
        output_json: str = None
    ) -> PackageDetectionResult:
        """
        检测整个包
        
        Args:
            package_path: 解压后的包路径
            package_manager: 包管理器类型，"npm" 或 "pypi"（默认）
            output_json: 输出JSON文件路径（可选）
            
        Returns:
            PackageDetectionResult 包检测结果
        """
        package_path = Path(package_path)
        package_name = package_path.name
        
        # 验证包管理器类型
        if package_manager not in ["npm", "pypi"]:
            raise ValueError(f"不支持的包管理器: {package_manager}，仅支持 'npm' 或 'pypi'")
        
        logger.info(f"\n{'='*80}")
        logger.info(f"开始检测包: {package_name}")
        logger.info(f"包管理器: {package_manager.upper()}")
        logger.info(f"路径: {package_path}")
        logger.info(f"{'='*80}\n")
        
        # 1. 根据包管理器类型扫描文件
        code_files = self._scan_code_files(package_path, package_manager)
        file_type = "Python" if package_manager == "pypi" else "JavaScript"
        logger.info(f"📁 发现 {len(code_files)} 个{file_type}文件")
        
        if len(code_files) == 0:
            logger.warning(f"⚠️  未发现任何{file_type}文件")
            return self._create_empty_result(package_name, str(package_path))
        
        # 2. 对每个文件进行切片和检测
        file_results = []
        total_slices = 0
        malicious_slices = 0
        
        for i, code_file in enumerate(code_files, 1):
            logger.info(f"\n[{i}/{len(code_files)}] 处理文件: {code_file.relative_to(package_path)}")
            
            file_result = self._detect_file(code_file)
            file_results.append(file_result)
            
            if file_result.status == "success":
                total_slices += file_result.total_slices
                malicious_slices += file_result.malicious_slices
                
                status_icon = "🔴" if file_result.is_malicious else "🟢"
                logger.info(f"  {status_icon} 切片: {file_result.total_slices}, 恶意: {file_result.malicious_slices}")
        
        # 3. 汇总包级结果
        is_malicious_package = malicious_slices > 0
        
        result = PackageDetectionResult(
            package_name=package_name,
            package_path=str(package_path),
            total_files=len(code_files),
            processed_files=sum(1 for f in file_results if f.status == "success"),
            total_slices=total_slices,
            malicious_slices=malicious_slices,
            is_malicious_package=is_malicious_package,
            file_results=file_results,
            detection_timestamp=datetime.now().isoformat(),
            kb_info={
                "total_packages": len(self.kb.packages),
                "total_snippets": len(self.kb.snippet_index)
            }
        )
        
        # 4. 输出结果
        self._print_summary(result)
        
        # 5. 保存JSON
        if output_json:
            self._save_result(result, output_json)
        
        return result
    
    def _scan_code_files(self, package_path: Path, package_manager: str) -> List[Path]:
        """
        根据包管理器类型扫描代码文件
        
        Args:
            package_path: 包路径
            package_manager: "npm" 或 "pypi"
            
        Returns:
            代码文件路径列表
        """
        # 排除常见的虚拟环境和缓存目录
        exclude_dirs = {'venv', 'env', '.venv', '__pycache__', '.git', 'node_modules', 
                       'dist', 'build', '.next', '.nuxt', 'coverage', '.cache'}
        
        code_files = []
        
        if package_manager == "pypi":
            # PyPI: 扫描所有.py文件
            if package_path.is_file() and package_path.suffix == '.py':
                return [package_path]
            
            for py_file in package_path.rglob('*.py'):
                if not any(excluded in py_file.parts for excluded in exclude_dirs):
                    code_files.append(py_file)
        
        elif package_manager == "npm":
            # NPM: 扫描package.json和所有.js文件
            
            # 1. 查找package.json
            package_json = package_path / "package.json"
            if package_json.exists():
                code_files.append(package_json)
            
            # 2. 查找所有.js文件
            if package_path.is_file() and package_path.suffix == '.js':
                code_files.append(package_path)
            else:
                for js_file in package_path.rglob('*.js'):
                    if not any(excluded in js_file.parts for excluded in exclude_dirs):
                        code_files.append(js_file)
        
        return code_files
    
    def _detect_file(self, file_path: Path) -> FileDetectionResult:
        """检测单个文件"""
        try:
            # 1. 代码切片
            slice_result = self.slicer.slice_file(str(file_path))
            
            if slice_result["status"] != "success":
                return FileDetectionResult(
                    file_path=str(file_path),
                    status=slice_result["status"],
                    total_slices=0,
                    malicious_slices=0,
                    is_malicious=False,
                    slice_results=[],
                    error=slice_result.get("error")
                )
            
            slices = slice_result.get("slices", [])
            
            if len(slices) == 0:
                return FileDetectionResult(
                    file_path=str(file_path),
                    status="empty",
                    total_slices=0,
                    malicious_slices=0,
                    is_malicious=False,
                    slice_results=[]
                )
            
            # 2. 对每个切片进行RAG检测
            slice_detections = []
            malicious_count = 0
            
            for slice_data in slices:
                detection = self._detect_slice(slice_data, str(file_path))
                slice_detections.append(detection)
                
                if detection.is_malicious:
                    malicious_count += 1
            
            # 3. 返回文件结果
            return FileDetectionResult(
                file_path=str(file_path),
                status="success",
                total_slices=len(slices),
                malicious_slices=malicious_count,
                is_malicious=(malicious_count > 0),
                slice_results=slice_detections
            )
            
        except Exception as e:
            logger.error(f"处理文件出错 {file_path}: {e}")
            return FileDetectionResult(
                file_path=str(file_path),
                status="error",
                total_slices=0,
                malicious_slices=0,
                is_malicious=False,
                slice_results=[],
                error=str(e)
            )
    
    def _detect_slice(self, slice_data: Dict[str, Any], file_path: str) -> SliceDetectionResult:
        """检测单个切片"""
        code = slice_data.get("code", "")
        behavior = slice_data.get("behavior_summary", "")
        slice_id = slice_data.get("slice_id", "unknown")
        
        # 使用RAG检测器
        rag_result: DetectionResult = self.detector.detect(
            code_snippet=code,
            code_behavior=behavior,
            malice_threshold=self.malice_threshold
        )
        
        # 转换matched_knowledge为字典列表（包含完整的RAG信息）
        matched_dicts = []
        for match in rag_result.matched_knowledge:
            matched_dicts.append({
                # 基本匹配信息
                "match_id": match.match_id,
                "source_package": match.source_package,
                "source_file": match.source_file,
                "match_type": match.match_type,
                
                # 相似度分数
                "similarity_score": match.similarity_score,
                "code_similarity": match.code_similarity,
                "behavior_similarity": match.behavior_similarity,
                
                # 完整的匹配片段信息（来自知识库）
                "matched_snippet": {
                    # 代码片段信息
                    "snippet_id": match.matched_snippet.get('snippet_id', ''),
                    "code_snippet": match.matched_snippet.get('code_snippet', ''),
                    "code_behavior": match.matched_snippet.get('code_behavior', ''),
                    
                    # 恶意分析
                    "malice_analysis": match.matched_snippet.get('malice_analysis', {}),
                    
                    # 执行上下文
                    "execution_context": match.matched_snippet.get('execution_context', {}),
                    
                    # 包级别信息
                    "package_info": {
                        "package_name": match.matched_snippet.get('package_name', ''),
                        "package_manager": match.matched_snippet.get('package_manager', ''),
                        "package_versions": match.matched_snippet.get('package_versions', ''),
                        "why_malicious": match.matched_snippet.get('why_malicious', '')
                    },
                    
                    # 攻击链信息
                    "attack_chain": match.matched_snippet.get('attack_chain', {}),
                    
                    # 检测知识
                    "detection_knowledge": match.matched_snippet.get('detection_knowledge', {})
                }
            })
        
        return SliceDetectionResult(
            slice_id=slice_id,
            file_path=file_path,
            code_snippet=code,
            behavior_summary=behavior,
            is_malicious=rag_result.is_malicious,
            malice_score=rag_result.malice_score,
            confidence=rag_result.confidence,
            explanation=rag_result.explanation,
            matched_knowledge=matched_dicts
        )
    
    def _create_empty_result(self, package_name: str, package_path: str) -> PackageDetectionResult:
        """创建空结果"""
        return PackageDetectionResult(
            package_name=package_name,
            package_path=package_path,
            total_files=0,
            processed_files=0,
            total_slices=0,
            malicious_slices=0,
            is_malicious_package=False,
            file_results=[],
            detection_timestamp=datetime.now().isoformat(),
            kb_info={
                "total_packages": len(self.kb.packages),
                "total_snippets": len(self.kb.snippet_index)
            }
        )
    
    def _print_summary(self, result: PackageDetectionResult):
        """打印检测摘要"""
        logger.info(f"\n{'='*80}")
        logger.info("📊 检测结果汇总")
        logger.info(f"{'='*80}")
        
        verdict = "🔴 恶意包" if result.is_malicious_package else "🟢 正常包"
        logger.info(f"\n判定结果: {verdict}")
        logger.info(f"包名: {result.package_name}")
        logger.info(f"\n统计信息:")
        logger.info(f"  - 扫描文件: {result.total_files}")
        logger.info(f"  - 成功处理: {result.processed_files}")
        logger.info(f"  - 代码切片: {result.total_slices}")
        logger.info(f"  - 恶意切片: {result.malicious_slices}")
        
        if result.total_slices > 0:
            malice_rate = result.malicious_slices / result.total_slices * 100
            logger.info(f"  - 恶意率: {malice_rate:.2f}%")
        
        if result.is_malicious_package:
            logger.info(f"\n⚠️  发现恶意代码！")
            logger.info(f"恶意文件列表:")
            for file_result in result.file_results:
                if file_result.is_malicious:
                    logger.info(f"  🔴 {file_result.file_path}")
                    logger.info(f"     恶意切片: {file_result.malicious_slices}/{file_result.total_slices}")
        
        logger.info(f"\n{'='*80}\n")
    
    def _save_result(self, result: PackageDetectionResult, output_path: str):
        """保存结果到JSON"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ 检测结果已保存到: {output_path}")
        logger.info(f"   文件大小: {output_path.stat().st_size / 1024:.2f} KB")


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='端到端恶意包检测系统（支持npm和pypi）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法：
  # 检测PyPI包
  python package_detector.py /path/to/package -m pypi
  
  # 检测npm包
  python package_detector.py /path/to/package -m npm
  
  # 指定输出文件和阈值
  python package_detector.py /path/to/package -m npm -o report.json -t 0.6
        """
    )
    
    parser.add_argument('package_path', help='解压后的包路径')
    parser.add_argument('-m', '--manager', 
                       choices=['npm', 'pypi'], 
                       default='pypi',
                       help='包管理器类型 (默认: pypi)')
    parser.add_argument('-o', '--output', help='输出JSON文件路径')
    parser.add_argument('-t', '--threshold', type=float, default=0.5, 
                       help='恶意判定阈值 (默认: 0.5)')
    parser.add_argument('--kb-path', help='知识库路径 (默认: 项目根目录/KnowledgeBase)')
    
    args = parser.parse_args()
    
    # 默认输出路径
    if not args.output:
        package_name = Path(args.package_path).name
        project_root = Path(__file__).parent.parent.parent
        output_dir = project_root / "Results" / "malware_detection"
        output_dir.mkdir(parents=True, exist_ok=True)
        args.output = str(output_dir / f"{package_name}_report.json")
    
    # 初始化检测器
    detector = PackageMalwareDetector(
        kb_path=args.kb_path,
        malice_threshold=args.threshold
    )
    
    # 执行检测
    result = detector.detect_package(
        package_path=args.package_path,
        package_manager=args.manager,
        output_json=args.output
    )
    
    # 返回状态码
    return 1 if result.is_malicious_package else 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

