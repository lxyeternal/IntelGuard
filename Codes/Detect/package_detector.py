"""End-to-end malicious package detection for npm and PyPI packages."""

import os
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
import logging
from multiprocessing import Pool, cpu_count

project_root = str(Path(__file__).parent.parent.parent)
sys.path.insert(0, project_root)

from Codes.Detect.static.static_slice import StaticCodeSlicer
from Codes.KnowledgeBase.rag_detector import RAGMalwareDetector, RAGKnowledgeBase, DetectionResult
from Codes.GPTAnalysis.llmquery import LLMAgent

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def _process_slices_worker(args: tuple) -> "FileDetectionResult":
    """Worker: judge the slices of one file."""
    file_path, slice_result, kb_path = args
    try:
        from Codes.KnowledgeBase.rag_detector import RAGMalwareDetector, RAGKnowledgeBase
        kb = RAGKnowledgeBase(kb_path=kb_path)
        kb.load_kb()
        detector = RAGMalwareDetector(knowledge_base=kb)
        if slice_result["status"] != "success":
            return FileDetectionResult(file_path=str(file_path), status=slice_result["status"], total_slices=0,
                                       malicious_slices=0, is_malicious=False, slice_results=[],
                                       error=slice_result.get("error"))
        slices = slice_result.get("slices", [])
        if not slices:
            return FileDetectionResult(file_path=str(file_path), status="empty", total_slices=0,
                                       malicious_slices=0, is_malicious=False, slice_results=[])
        dets = [_detect_slice_worker(sd, str(file_path), detector) for sd in slices]
        mal = sum(1 for d in dets if d.is_malicious)
        return FileDetectionResult(file_path=str(file_path), status="success", total_slices=len(slices),
                                   malicious_slices=mal, is_malicious=mal > 0, slice_results=dets)
    except Exception as e:
        return FileDetectionResult(file_path=str(file_path), status="error", total_slices=0, malicious_slices=0,
                                   is_malicious=False, slice_results=[], error=str(e))


def _slice_meta(slice_data: Dict[str, Any]) -> Dict[str, Any]:
    """Slice provenance kept in the report."""
    keys = ("sensitive_apis", "categories", "trigger", "entry_chain", "lines", "cross_file", "n_lines",
            "criteria_lines", "function")
    return {k: slice_data[k] for k in keys if k in slice_data}


def _detect_slice_worker(
    slice_data: Dict[str, Any], 
    file_path: str, 
    detector
) -> "SliceDetectionResult":
    """Judge one slice with the detector."""
    from Codes.KnowledgeBase.rag_detector import DetectionResult
    
    code = slice_data.get("code", "")
    behavior = slice_data.get("behavior_summary", "")
    slice_id = slice_data.get("slice_id", "unknown")
    
    rag_result: DetectionResult = detector.detect(
        code_snippet=code,
        code_behavior=behavior
    )
    
    matched_dicts = []
    for match in rag_result.matched_knowledge:
        matched_dicts.append({
            "match_id": match.match_id,
            "source_package": match.source_package,
            "source_file": match.source_file,
            "match_type": match.match_type,
            
            "similarity_score": match.similarity_score,
            "code_similarity": match.code_similarity,
            "behavior_similarity": match.behavior_similarity,
            
            "matched_snippet": {
                "snippet_id": match.matched_snippet.get('snippet_id', ''),
                "code_snippet": match.matched_snippet.get('code_snippet', ''),
                "code_behavior": match.matched_snippet.get('code_behavior', ''),
                "malice_analysis": match.matched_snippet.get('malice_analysis', {}),
                "execution_context": match.matched_snippet.get('execution_context', {}),
                "package_info": {
                    "package_name": match.matched_snippet.get('package_name', ''),
                    "package_manager": match.matched_snippet.get('package_manager', ''),
                    "package_versions": match.matched_snippet.get('package_versions', ''),
                    "why_malicious": match.matched_snippet.get('why_malicious', '')
                },
                "attack_chain": match.matched_snippet.get('attack_chain', {}),
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
        matched_knowledge=matched_dicts,
        slice_meta=_slice_meta(slice_data)
    )


def _process_package_worker(args: tuple) -> "PackageDetectionResult":
    """Worker: detect one package."""
    package_path, package_manager, kb_path = args
    
    detector = PackageMalwareDetector(
        kb_path=kb_path
    )
    
    return detector.detect_package(
        package_path=package_path,
        package_manager=package_manager,
        output_json=None,
        num_processes=1
    )


@dataclass
class SliceDetectionResult:
    """Verdict of one slice."""
    slice_id: str
    file_path: str
    code_snippet: str
    behavior_summary: str
    
    is_malicious: bool
    malice_score: float
    confidence: float
    explanation: str
    
    matched_knowledge: List[Dict[str, Any]]
    slice_meta: Dict[str, Any] = None
    
    def to_dict(self):
        """Serialise to a dict."""
        return {
            "slice_id": self.slice_id,
            "file_path": self.file_path,
            "code_snippet": self.code_snippet[:500] + "..." if len(self.code_snippet) > 500 else self.code_snippet,
            "behavior_summary": self.behavior_summary,
            "detection_result": {
                "is_malicious": self.is_malicious,
                "slice_meta": self.slice_meta or {},
                "malice_score": round(self.malice_score, 4),
                "confidence": round(self.confidence, 4),
                "explanation": self.explanation
            },
            "top_matches": [
                {
                    "match_id": m["match_id"],
                    "source_package": m["source_package"],
                    "source_file": m["source_file"],
                    "match_type": m["match_type"],
                    
                    "similarity_score": round(m["similarity_score"], 4),
                    "code_similarity": round(m["code_similarity"], 4),
                    "behavior_similarity": round(m["behavior_similarity"], 4),
                    
                    "matched_snippet": m["matched_snippet"]
                }
                for m in self.matched_knowledge[:3]
            ]
        }


@dataclass  
class FileDetectionResult:
    """Verdicts of one file."""
    file_path: str
    status: str
    total_slices: int
    malicious_slices: int
    is_malicious: bool
    
    slice_results: List[SliceDetectionResult]
    error: Optional[str] = None
    
    def to_dict(self):
        """Serialise to a dict."""
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
    """Verdict of one package."""
    package_name: str
    package_path: str
    
    total_files: int
    processed_files: int
    total_slices: int
    malicious_slices: int
    
    is_malicious_package: bool
    
    file_results: List[FileDetectionResult]
    
    detection_timestamp: str
    kb_info: Dict[str, Any]
    
    @property
    def malicious_files(self) -> int:
        """Number of files with a malicious slice."""
        return sum(1 for f in self.file_results if f.malicious_slices > 0)
    
    def to_dict(self):
        """Serialise to a dict."""
        return {
            "package_info": {
                "package_name": self.package_name,
                "package_path": self.package_path,
                "detection_timestamp": self.detection_timestamp
            },
            "detection_summary": {
                "is_malicious_package": self.is_malicious_package,
                "verdict": "🔴 MALICIOUS" if self.is_malicious_package else "🟢 BENIGN",
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
    """Slice a package, retrieve knowledge and judge every slice."""
    
    def __init__(
        self, 
        kb_path: str = None,
        llm_agent: Optional[LLMAgent] = None,
        similarity_threshold: Optional[float] = None
    ):
        """Create the slicer, load the knowledge base and the LLM agent."""
        if kb_path is None:
            project_root = Path(__file__).parent.parent.parent
            kb_path = os.environ.get("INTELGUARD_KB_PATH") or str(project_root / "KnowledgeBase")

        if llm_agent is None:
            logger.info("No llm_agent given; creating an LLMAgent")
            llm_agent = LLMAgent()

        logger.info("Initializing the package detector...")

        logger.info("[1/3] Initializing the code slicer...")
        self.slicer = StaticCodeSlicer(llm_agent=llm_agent)
        
        logger.info("[2/3] Loading the knowledge base...")
        logger.info(f"   Knowledge base path: {kb_path}")
        self.kb = RAGKnowledgeBase(kb_path=kb_path)
        
        try:
            self.kb.load_kb()
            logger.info(f"   ✓ Loaded knowledge base: {len(self.kb.packages)} packages, {len(self.kb.snippet_index)} snippets")
        except FileNotFoundError as e:
            logger.warning(f"   ⚠️  Knowledge base not found: {e}")
            logger.warning(f"   Run Codes/KnowledgeBase/build_knowledge_base.py first")
        except Exception as e:
            logger.error(f"   ❌ Failed to load the knowledge base: {e}")
            import traceback
            traceback.print_exc()
        
        logger.info("[3/3] Initializing the detector...")
        if similarity_threshold is not None:
            logger.info(f"   Similarity threshold: {similarity_threshold}")
        self.detector = RAGMalwareDetector(
            knowledge_base=self.kb, 
            llm_agent=llm_agent,
            similarity_threshold=similarity_threshold
        )
        
        logger.info("✅ Detector ready")
    
    def detect_package(
        self, 
        package_path: str, 
        package_manager: str = "pypi",
        output_json: str = None,
        num_processes: int = 1
    ) -> PackageDetectionResult:
        """Detect one package and optionally write the JSON report."""
        package_path = Path(package_path)
        package_name = package_path.name
        
        if package_manager not in ["npm", "pypi"]:
            raise ValueError(f"Unsupported package manager: {package_manager} (use 'npm' or 'pypi')")
        
        logger.info(f"\n{'='*80}")
        logger.info(f"Detecting package: {package_name}")
        logger.info(f"Package manager: {package_manager.upper()}")
        logger.info(f"Path: {package_path}")
        logger.info(f"{'='*80}\n")
        
        code_files = [Path(f) for f in self.slicer._scan(str(package_path), package_manager)]
        file_type = "Python" if package_manager == "pypi" else "JavaScript"
        logger.info(f"📁 Found {len(code_files)} {file_type} files")
        
        if len(code_files) == 0:
            logger.warning(f"⚠️  No {file_type} file found")
            return self._create_empty_result(package_name, str(package_path))
        
        self.slicer.prepare_package(str(package_path), package_manager, [str(f) for f in code_files])
        
        if num_processes == 0:
            num_processes = min(cpu_count(), len(code_files))
        num_processes = max(1, num_processes)
        
        if num_processes == 1:
            logger.info("🔧 Running in one process")
            file_results = self._detect_files_sequential(code_files, package_path)
        else:
            logger.info(f"🚀 Running with {num_processes} processes")
            file_results = self._detect_files_parallel_presliced(code_files, num_processes, package_path)
        
        total_slices = 0
        malicious_slices = 0
        for file_result in file_results:
            if file_result.status == "success":
                total_slices += file_result.total_slices
                malicious_slices += file_result.malicious_slices
        
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
                "total_snippets": len(self.kb.snippet_index),
                "slicer": "static",
                "slicer_stats": getattr(self.slicer, "stats", {}),
                "clusters": self.kb.cluster_summary() if hasattr(self.kb, "cluster_summary") else {}
            }
        )
        
        self._print_summary(result)
        
        if output_json:
            self._save_result(result, output_json)
        
        return result
    
    def _detect_files_sequential(self, code_files: List[Path], package_path: Path) -> List[FileDetectionResult]:
        """Slice and judge files one by one."""
        file_results = []
        
        for i, code_file in enumerate(code_files, 1):
            logger.info(f"\n[{i}/{len(code_files)}] Processing {code_file.relative_to(package_path)}")
            
            file_result = self._detect_file(code_file)
            file_results.append(file_result)
            
            if file_result.status == "success":
                status_icon = "🔴" if file_result.is_malicious else "🟢"
                logger.info(f"  {status_icon} slices: {file_result.total_slices}, malicious: {file_result.malicious_slices}")
        
        return file_results
    
    def _detect_files_parallel_presliced(self, code_files: List[Path], num_processes: int, package_path: Path) -> List[FileDetectionResult]:
        """Slice in the parent and judge in worker processes."""
        kb_path = str(self.kb.kb_path)
        jobs = [(str(f), self.slicer.slice_file(str(f)), kb_path) for f in code_files]
        logger.info(f"  Slicing done: {sum(len(j[1].get('slices', [])) for j in jobs)} slices; starting {num_processes} workers...")
        file_results = []
        with Pool(processes=num_processes) as pool:
            for i, result in enumerate(pool.imap(_process_slices_worker, jobs), 1):
                file_results.append(result)
                relative_path = Path(result.file_path).relative_to(package_path)
                if result.status == "success":
                    status_icon = "🔴" if result.is_malicious else "🟢"
                    logger.info(f"[{i}/{len(jobs)}] {status_icon} {relative_path} - slices: {result.total_slices}, malicious: {result.malicious_slices}")
                else:
                    logger.info(f"[{i}/{len(jobs)}] ⚠️  {relative_path} - {result.status}")
        return file_results

    def _detect_file(self, file_path: Path) -> FileDetectionResult:
        """Slice and judge one file."""
        try:
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
            
            slice_detections = []
            malicious_count = 0
            
            for slice_data in slices:
                detection = self._detect_slice(slice_data, str(file_path))
                slice_detections.append(detection)
                
                if detection.is_malicious:
                    malicious_count += 1
            
            return FileDetectionResult(
                file_path=str(file_path),
                status="success",
                total_slices=len(slices),
                malicious_slices=malicious_count,
                is_malicious=(malicious_count > 0),
                slice_results=slice_detections
            )
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
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
        """Judge one slice."""
        code = slice_data.get("code", "")
        behavior = slice_data.get("behavior_summary", "")
        slice_id = slice_data.get("slice_id", "unknown")
        
        rag_result: DetectionResult = self.detector.detect(
            code_snippet=code,
            code_behavior=behavior
        )
        
        matched_dicts = []
        for match in rag_result.matched_knowledge:
            matched_dicts.append({
                "match_id": match.match_id,
                "source_package": match.source_package,
                "source_file": match.source_file,
                "match_type": match.match_type,
                
                "similarity_score": match.similarity_score,
                "code_similarity": match.code_similarity,
                "behavior_similarity": match.behavior_similarity,
                
                "matched_snippet": {
                    "snippet_id": match.matched_snippet.get('snippet_id', ''),
                    "code_snippet": match.matched_snippet.get('code_snippet', ''),
                    "code_behavior": match.matched_snippet.get('code_behavior', ''),
                    
                    "malice_analysis": match.matched_snippet.get('malice_analysis', {}),
                    
                    "execution_context": match.matched_snippet.get('execution_context', {}),
                    
                    "package_info": {
                        "package_name": match.matched_snippet.get('package_name', ''),
                        "package_manager": match.matched_snippet.get('package_manager', ''),
                        "package_versions": match.matched_snippet.get('package_versions', ''),
                        "why_malicious": match.matched_snippet.get('why_malicious', '')
                    },
                    
                    "attack_chain": match.matched_snippet.get('attack_chain', {}),
                    
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
            matched_knowledge=matched_dicts,
            slice_meta=_slice_meta(slice_data)
        )
    
    def _create_empty_result(self, package_name: str, package_path: str) -> PackageDetectionResult:
        """Result for a package without code files."""
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
        """Log the package verdict."""
        logger.info(f"\n{'='*80}")
        logger.info("📊 Detection summary")
        logger.info(f"{'='*80}")
        
        verdict = "🔴 malicious" if result.is_malicious_package else "🟢 benign"
        logger.info(f"\nVerdict: {verdict}")
        logger.info(f"Package: {result.package_name}")
        logger.info(f"\nStatistics:")
        logger.info(f"  - files scanned: {result.total_files}")
        logger.info(f"  - files processed: {result.processed_files}")
        logger.info(f"  - slices: {result.total_slices}")
        logger.info(f"  - malicious slices: {result.malicious_slices}")
        
        if result.total_slices > 0:
            malice_rate = result.malicious_slices / result.total_slices * 100
            logger.info(f"  - malicious rate: {malice_rate:.2f}%")
        
        if result.is_malicious_package:
            logger.info(f"\n⚠️  Malicious code found")
            logger.info(f"Malicious files:")
            for file_result in result.file_results:
                if file_result.is_malicious:
                    logger.info(f"  🔴 {file_result.file_path}")
                    logger.info(f"     malicious slices: {file_result.malicious_slices}/{file_result.total_slices}")
        
        logger.info(f"\n{'='*80}\n")
    
    def _save_result(self, result: PackageDetectionResult, output_path: str):
        """Write the JSON report."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ Report written to: {output_path}")
        logger.info(f"   Size: {output_path.stat().st_size / 1024:.2f} KB")


def batch_detect_packages(
    package_paths: List[str],
    package_manager: str = "pypi",
    kb_path: str = None,
    num_processes: int = 1
) -> int:
    """Detect several packages in parallel."""
    logger.info(f"\n{'='*80}")
    logger.info(f"📦 Batch detection: {len(package_paths)} packages")
    logger.info(f"{'='*80}\n")
    
    if kb_path is None:
        project_root = Path(__file__).parent.parent.parent
        kb_path = str(project_root / "KnowledgeBase")
    
    if num_processes == 0:
        num_processes = min(cpu_count(), len(package_paths))
    num_processes = max(1, num_processes)
    
    project_root = Path(__file__).parent.parent.parent
    output_dir = project_root / "Results" / "malware_detection" / "batch"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if num_processes == 1:
        logger.info("🔧 Running in one process")
        detector = PackageMalwareDetector(
            kb_path=kb_path
        )
        
        results = []
        for i, pkg_path in enumerate(package_paths, 1):
            logger.info(f"\n[{i}/{len(package_paths)}] Detecting {pkg_path}")
            
            output_file = output_dir / f"{Path(pkg_path).name}_report.json"
            result = detector.detect_package(
                package_path=pkg_path,
                package_manager=package_manager,
                output_json=str(output_file),
                num_processes=1
            )
            results.append(result)
    else:
        logger.info(f"🚀 Running with {num_processes} processes")
        
        args_list = [
            (pkg_path, package_manager, kb_path)
            for pkg_path in package_paths
        ]
        
        with Pool(processes=num_processes) as pool:
            results = list(pool.imap(_process_package_worker, args_list))
        
        for result in results:
            output_file = output_dir / f"{result.package_name}_report.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info(f"✅ Saved: {output_file}")
    
    logger.info(f"\n{'='*80}")
    logger.info("📊 Batch summary")
    logger.info(f"{'='*80}")
    
    total_packages = len(results)
    malicious_packages = sum(1 for r in results if r.is_malicious_package)
    clean_packages = total_packages - malicious_packages
    
    logger.info(f"Packages: {total_packages}")
    logger.info(f"🔴 malicious: {malicious_packages}")
    logger.info(f"🟢 benign: {clean_packages}")
    
    if malicious_packages > 0:
        logger.info(f"\n⚠️  {malicious_packages} malicious packages:")
        for result in results:
            if result.is_malicious_package:
                logger.info(f"  🔴 {result.package_name} (malicious slices: {result.malicious_slices}/{result.total_slices})")
    
    logger.info(f"\n{'='*80}\n")
    
    return malicious_packages


def main():
    """Command line entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Malicious package detection for npm and PyPI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python package_detector.py /path/to/package -m pypi
  python package_detector.py /path/to/package -m npm -j 4
  python package_detector.py /path/to/package -j 0
  python package_detector.py pkg1 --batch pkg1/ pkg2/ pkg3/ -j 3
  python package_detector.py /path/to/package -o report.json -t 0.6
        """
    )
    
    parser.add_argument('package_path', nargs='?', help='path of the unpacked package (optional with --batch)')
    parser.add_argument('-m', '--manager', 
                       choices=['npm', 'pypi'], 
                       default='pypi',
                       help='package manager (default: pypi)')
    parser.add_argument('-o', '--output', help='output JSON file')
    parser.add_argument('-t', '--threshold', type=float, default=0.5, 
                       help='malice threshold (default: 0.5)')
    parser.add_argument('--kb-path', help='knowledge base dir (default: <repo>/KnowledgeBase)')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                       help='number of processes (0 = cpu count, default: 1)')
    parser.add_argument('--batch', nargs='+', metavar='PATH',
                       help='detect several packages')
    
    args = parser.parse_args()
    
    if not args.batch and not args.package_path:
        parser.error("package_path or --batch is required")
    
    if args.batch:
        return batch_detect_packages(
            package_paths=args.batch,
            package_manager=args.manager,
            kb_path=args.kb_path,
            num_processes=args.jobs
        )
    
    if not args.output:
        package_name = Path(args.package_path).name
        project_root = Path(__file__).parent.parent.parent
        output_dir = project_root / "Results" / "malware_detection"
        output_dir.mkdir(parents=True, exist_ok=True)
        args.output = str(output_dir / f"{package_name}_report.json")
    
    detector = PackageMalwareDetector(
        kb_path=args.kb_path
    )
    
    result = detector.detect_package(
        package_path=args.package_path,
        package_manager=args.manager,
        output_json=args.output,
        num_processes=args.jobs
    )
    
    return 1 if result.is_malicious_package else 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

