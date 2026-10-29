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
        logger.info(f"📚 构建RAG知识库（最多 {MAX_SAMPLES} 个样本，{NUM_WORKERS} 进程）")
    else:
        logger.info(f"📚 构建RAG知识库（使用全部样本，{NUM_WORKERS} 进程）")
    logger.info("=" * 80)
    logger.info(f"数据源目录: {intelli_json_dir}")
    logger.info(f"知识库保存路径: {kb_path}")
    
    if not intelli_json_dir.exists():
        logger.error(f"❌ 数据源目录不存在: {intelli_json_dir}")
        return
    
    all_verify_files = list(intelli_json_dir.rglob("verify.json"))
    logger.info(f"找到 {len(all_verify_files)} 个verify.json文件")
    
    if len(all_verify_files) == 0:
        logger.error("❌ 未找到任何verify.json文件！")
        return
    
    if MAX_SAMPLES and MAX_SAMPLES < len(all_verify_files):
        selected_files = random.sample(all_verify_files, MAX_SAMPLES)
        logger.info(f"📌 随机选择了 {len(selected_files)} 个文件用于构建知识库")
    else:
        selected_files = all_verify_files
        logger.info(f"📌 使用全部 {len(selected_files)} 个文件构建知识库")
    
    logger.info("")
    
    logger.info("选中的文件示例（前10个）:")
    for i, f in enumerate(selected_files[:10], 1):
        package_name = f.parent.name
        logger.info(f"  {i}. {package_name}")
    if len(selected_files) > 10:
        logger.info(f"  ... 还有 {len(selected_files) - 10} 个文件")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="kb_build_"))
    logger.info(f"\n临时目录: {temp_dir}")
    
    try:
        existing_kb_file = kb_path / "knowledge_base.json"
        existing_packages = set()
        
        if existing_kb_file.exists():
            logger.info(f"\n📦 检测到已有知识库: {existing_kb_file}")
            try:
                with open(existing_kb_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    existing_packages = {pkg['kb_id'] for pkg in existing_data.get('packages', [])}
                    logger.info(f"   已有 {len(existing_packages)} 个包在知识库中")
            except Exception as e:
                logger.warning(f"   读取已有知识库失败: {e}，将重新构建")
                existing_packages = set()
        
        report_ids = unique_report_ids(all_verify_files)
        new_files = [f for f in selected_files if report_ids[f] not in existing_packages]
        if len(new_files) == 0:
            logger.info("✅ 知识库已包含全部报告，刷新聚类")
            from Codes.KnowledgeBase.cluster_knowledge import build_clusters
            cl = build_clusters(kb_path)
            logger.info(f"  - 代码簇: {len(cl['code'])}，行为簇: {len(cl['behavior'])}")
            return
        
        logger.info(f"📝 处理 {len(new_files)} 个报告")
        
        if NUM_WORKERS > 1:
            logger.info(f"\n⚡ 使用 {NUM_WORKERS} 进程并行处理文件...")
            
            with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
                future_to_file = {
                    executor.submit(process_single_verify_json, str(f)): f 
                    for f in new_files
                }
                
                with tqdm(total=len(new_files), desc="处理文件") as pbar:
                    for future in as_completed(future_to_file):
                        result = future.result()
                        
                        if result is not None:
                            target_dir = temp_dir / report_ids[future_to_file[future]]
                            target_dir.mkdir(parents=True, exist_ok=True)
                            
                            with open(target_dir / "verify.json", 'w', encoding='utf-8') as f:
                                json.dump(result['data'], f, ensure_ascii=False, indent=2)
                        
                        pbar.update(1)
        else:
            logger.info("\n📋 使用单进程处理文件...")
            for verify_file in tqdm(new_files, desc="复制文件"):
                target_dir = temp_dir / report_ids[verify_file]
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(verify_file, target_dir / "verify.json")
        
        logger.info("\n🔧 初始化知识库...")
        kb = RAGKnowledgeBase(kb_path=str(kb_path))
        
        logger.info("\n🚀 开始提取恶意代码片段并生成embeddings...")
        logger.info("这可能需要几分钟时间，请耐心等待...\n")
        
        kb.build_from_verify_jsons(str(temp_dir))
        
        logger.info("\n" + "=" * 80)
        logger.info("✅ 知识库构建完成！")
        logger.info("=" * 80)
        logger.info(f"📊 统计信息:")
        logger.info(f"  - 使用的包数量: {len(selected_files)}")
        logger.info(f"  - 总包数: {len(kb.packages)}")
        
        total_snippets = sum(len(pkg.get('malicious_snippets', [])) for pkg in kb.packages)
        logger.info(f"  - 总代码片段数: {total_snippets}")
        logger.info(f"  - 代码embeddings形状: {kb.code_embeddings.shape if kb.code_embeddings is not None else 'None'}")
        logger.info(f"  - 行为embeddings形状: {kb.behavior_embeddings.shape if kb.behavior_embeddings is not None else 'None'}")
        
        logger.info("\n📝 示例包信息:")
        for i, pkg in enumerate(kb.packages[:3], 1):
            logger.info(f"\n--- 包 {i} ---")
            logger.info(f"ID: {pkg['kb_id']}")
            logger.info(f"包名: {pkg.get('package_info', {}).get('package_name', 'N/A')}")
            logger.info(f"代码片段数: {len(pkg.get('malicious_snippets', []))}")
            if pkg.get('malicious_snippets'):
                snippet = pkg['malicious_snippets'][0]
                logger.info(f"首个片段代码: {snippet.get('code', '')[:100]}...")
        
        logger.info(f"\n💾 知识库文件已保存到:")
        logger.info(f"  - {kb_path / 'knowledge_base.json'}")
        logger.info(f"  - {kb_path / 'code_embeddings.npy'}")
        logger.info(f"  - {kb_path / 'behavior_embeddings.npy'}")
        
        logger.info("\n🔗 运行两级 HDBSCAN 知识聚类...")
        try:
            from Codes.KnowledgeBase.cluster_knowledge import build_clusters
            cl = build_clusters(kb_path)
            logger.info(f"  - 代码簇: {len(cl['code'])}，行为簇: {len(cl['behavior'])}")
        except Exception as e:
            logger.error(f"  聚类失败（知识库仍可用，检索退回片段级）: {e}")

        logger.info("\n✅ 知识库构建成功！现在可以用于恶意代码检测。")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"\n❌ 知识库构建失败: {e}", exc_info=True)
        return
    
    finally:
        logger.info(f"\n🧹 清理临时目录: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    random.seed(42)
    main()
