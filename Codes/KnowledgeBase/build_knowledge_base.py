"""Build the knowledge base from the verify.json reports."""

import sys
from pathlib import Path
import random
import tempfile
import shutil
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, Dict
from tqdm import tqdm

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.KnowledgeBase.rag_detector import RAGKnowledgeBase
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(processName)s] - %(message)s'
)
logger = logging.getLogger(__name__)

MAX_SAMPLES = None

NUM_WORKERS = 20


def unique_report_ids(verify_files):
    """Map each verify.json to its kb_id; same-named reports from different sources get a source prefix."""
    from collections import Counter
    counts = Counter(f.parent.name for f in verify_files)
    return {f: (f.parent.name if counts[f.parent.name] == 1 else f"{f.parent.parent.name}__{f.parent.name}")
            for f in verify_files}


def process_single_verify_json(verify_file_path: str) -> Optional[Dict]:
    """Build the knowledge entry of one verify.json in a worker process."""
    try:
        verify_file = Path(verify_file_path)
        
        with open(verify_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        package_info = data.get('package_info', {})
        if isinstance(package_info, list):
            package_info = package_info[0] if package_info else {}
        
        return {
            'kb_id': verify_file.parent.name,
            'source_file': str(verify_file),
            'data': data
        }
        
    except Exception as e:
        logger.error(f"Error processing {verify_file_path}: {e}")
        return None


def main():
    """Build the knowledge base and run the clustering."""
    
    intelli_json_dir = project_root / "Dataset" / "IntelliJson"
    kb_path = project_root / "KnowledgeBase"
    
    kb_path.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 80)
    if MAX_SAMPLES:
        logger.info(f"📚 Building knowledge base (at most {MAX_SAMPLES} reports, {NUM_WORKERS} workers)")
    else:
        logger.info(f"📚 Building knowledge base (all reports, {NUM_WORKERS} workers)")
    logger.info("=" * 80)
    logger.info(f"Report directory: {intelli_json_dir}")
    logger.info(f"Knowledge base path: {kb_path}")
    
    if not intelli_json_dir.exists():
        logger.error(f"❌ Report directory not found: {intelli_json_dir}")
        return
    
    all_verify_files = list(intelli_json_dir.rglob("verify.json"))
    logger.info(f"Found {len(all_verify_files)} verify.json files")
    
    if len(all_verify_files) == 0:
        logger.error("❌ No verify.json file found")
        return
    
    if MAX_SAMPLES and MAX_SAMPLES < len(all_verify_files):
        selected_files = random.sample(all_verify_files, MAX_SAMPLES)
        logger.info(f"📌 Randomly selected {len(selected_files)} reports")
    else:
        selected_files = all_verify_files
        logger.info(f"📌 Using all {len(selected_files)} reports")
    
    logger.info("")
    
    logger.info("First 10 selected reports:")
    for i, f in enumerate(selected_files[:10], 1):
        package_name = f.parent.name
        logger.info(f"  {i}. {package_name}")
    if len(selected_files) > 10:
        logger.info(f"  ... and {len(selected_files) - 10} more")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="kb_build_"))
    logger.info(f"\nTemporary directory: {temp_dir}")
    
    try:
        existing_kb_file = kb_path / "knowledge_base.json"
        existing_packages = set()
        
        if existing_kb_file.exists():
            logger.info(f"\n📦 Existing knowledge base: {existing_kb_file}")
            try:
                with open(existing_kb_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    existing_packages = {pkg['kb_id'] for pkg in existing_data.get('packages', [])}
                    logger.info(f"   {len(existing_packages)} packages in the knowledge base")
            except Exception as e:
                logger.warning(f"   Failed to read the knowledge base: {e}; rebuilding")
                existing_packages = set()
        
        report_ids = unique_report_ids(all_verify_files)
        new_files = [f for f in selected_files if report_ids[f] not in existing_packages]
        if len(new_files) == 0:
            logger.info("✅ All reports are in the knowledge base; refreshing clusters")
            from Codes.KnowledgeBase.cluster_knowledge import build_clusters
            cl = build_clusters(kb_path)
            logger.info(f"  - code clusters: {len(cl['code'])}, behavior clusters: {len(cl['behavior'])}")
            return
        
        logger.info(f"📝 Processing {len(new_files)} reports")
        
        if NUM_WORKERS > 1:
            logger.info(f"\n⚡ Processing reports with {NUM_WORKERS} workers...")
            
            with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
                future_to_file = {
                    executor.submit(process_single_verify_json, str(f)): f 
                    for f in new_files
                }
                
                with tqdm(total=len(new_files), desc="reports") as pbar:
                    for future in as_completed(future_to_file):
                        result = future.result()
                        
                        if result is not None:
                            target_dir = temp_dir / report_ids[future_to_file[future]]
                            target_dir.mkdir(parents=True, exist_ok=True)
                            
                            with open(target_dir / "verify.json", 'w', encoding='utf-8') as f:
                                json.dump(result['data'], f, ensure_ascii=False, indent=2)
                        
                        pbar.update(1)
        else:
            logger.info("\n📋 Processing reports in one process...")
            for verify_file in tqdm(new_files, desc="copying"):
                target_dir = temp_dir / report_ids[verify_file]
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(verify_file, target_dir / "verify.json")
        
        logger.info("\n🔧 Initializing the knowledge base...")
        kb = RAGKnowledgeBase(kb_path=str(kb_path))
        
        logger.info("\n🚀 Extracting malicious snippets and generating embeddings...")
        logger.info("This may take a few minutes...\n")
        
        kb.build_from_verify_jsons(str(temp_dir))
        
        logger.info("\n" + "=" * 80)
        logger.info("✅ Knowledge base built")
        logger.info("=" * 80)
        logger.info(f"📊 Statistics:")
        logger.info(f"  - reports used: {len(selected_files)}")
        logger.info(f"  - packages: {len(kb.packages)}")
        
        total_snippets = sum(len(pkg.get('malicious_snippets', [])) for pkg in kb.packages)
        logger.info(f"  - snippets: {total_snippets}")
        logger.info(f"  - code embeddings shape: {kb.code_embeddings.shape if kb.code_embeddings is not None else 'None'}")
        logger.info(f"  - behavior embeddings shape: {kb.behavior_embeddings.shape if kb.behavior_embeddings is not None else 'None'}")
        
        logger.info("\n📝 Sample packages:")
        for i, pkg in enumerate(kb.packages[:3], 1):
            logger.info(f"\n--- package {i} ---")
            logger.info(f"ID: {pkg['kb_id']}")
            logger.info(f"name: {pkg.get('package_info', {}).get('package_name', 'N/A')}")
            logger.info(f"snippets: {len(pkg.get('malicious_snippets', []))}")
            if pkg.get('malicious_snippets'):
                snippet = pkg['malicious_snippets'][0]
                logger.info(f"first snippet: {snippet.get('code', '')[:100]}...")
        
        logger.info(f"\n💾 Knowledge base files written to:")
        logger.info(f"  - {kb_path / 'knowledge_base.json'}")
        logger.info(f"  - {kb_path / 'code_embeddings.npy'}")
        logger.info(f"  - {kb_path / 'behavior_embeddings.npy'}")
        
        logger.info("\n🔗 Running two-level HDBSCAN clustering...")
        try:
            from Codes.KnowledgeBase.cluster_knowledge import build_clusters
            cl = build_clusters(kb_path)
            logger.info(f"  - code clusters: {len(cl['code'])}, behavior clusters: {len(cl['behavior'])}")
        except Exception as e:
            logger.error(f"  Clustering failed (retrieval falls back to snippet level): {e}")

        logger.info("\n✅ Knowledge base ready for detection.")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"\n❌ Knowledge base build failed: {e}", exc_info=True)
        return
    
    finally:
        logger.info(f"\n🧹 Removing temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    random.seed(42)
    main()
