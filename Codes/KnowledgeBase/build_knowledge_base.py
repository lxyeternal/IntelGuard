"""
构建RAG知识库

从verify.json文件中提取恶意代码片段，生成知识库

特性：
1. 支持通过MAX_SAMPLES参数控制使用的样本数量
2. 支持多进程并行处理以加速构建 (NUM_WORKERS参数)
3. 支持增量构建：自动跳过已处理的包，仅处理新增的包
4. 自动合并新旧embeddings，避免重复计算

使用方法：
- 首次运行：构建完整知识库
- 再次运行：自动检测已有知识库，仅添加新包
"""

import sys
from pathlib import Path
import random
import tempfile
import shutil
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, Dict
from tqdm import tqdm

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.KnowledgeBase.rag_detector import RAGKnowledgeBase
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(processName)s] - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ 配置参数 ============
# 最大样本数量 (设为None则使用全部样本)
MAX_SAMPLES = None  # 修改这个值来控制样本数量，例如: 50, 100, None(全部)

# 并行进程数量 (设为1则为单进程，设为4则为4进程并行)
NUM_WORKERS = 20  # 修改这个值来控制并行度，例如: 1(单进程), 4(4进程), 8(8进程)
# =================================


def process_single_verify_json(verify_file_path: str) -> Optional[Dict]:
    """
    处理单个verify.json文件（在子进程中运行）
    
    Args:
        verify_file_path: verify.json文件路径
    
    Returns:
        包含包信息的字典，如果失败返回None
    """
    try:
        verify_file = Path(verify_file_path)
        
        with open(verify_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 处理 package_info 可能是对象或数组的情况
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
    """构建知识库主函数"""
    
    # 配置路径
    intelli_json_dir = project_root / "Dataset" / "IntelliJson"
    kb_path = project_root / "KnowledgeBase"
    
    # 创建知识库目录
    kb_path.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 80)
    if MAX_SAMPLES:
        logger.info(f"📚 构建RAG知识库（最多 {MAX_SAMPLES} 个样本，{NUM_WORKERS} 进程）")
    else:
        logger.info(f"📚 构建RAG知识库（使用全部样本，{NUM_WORKERS} 进程）")
    logger.info("=" * 80)
    logger.info(f"数据源目录: {intelli_json_dir}")
    logger.info(f"知识库保存路径: {kb_path}")
    
    # 检查数据源是否存在
    if not intelli_json_dir.exists():
        logger.error(f"❌ 数据源目录不存在: {intelli_json_dir}")
        return
    
    # 统计所有verify.json文件
    all_verify_files = list(intelli_json_dir.rglob("verify.json"))
    logger.info(f"找到 {len(all_verify_files)} 个verify.json文件")
    
    if len(all_verify_files) == 0:
        logger.error("❌ 未找到任何verify.json文件！")
        return
    
    # 根据MAX_SAMPLES选择文件
    if MAX_SAMPLES and MAX_SAMPLES < len(all_verify_files):
        selected_files = random.sample(all_verify_files, MAX_SAMPLES)
        logger.info(f"📌 随机选择了 {len(selected_files)} 个文件用于构建知识库")
    else:
        selected_files = all_verify_files
        logger.info(f"📌 使用全部 {len(selected_files)} 个文件构建知识库")
    
    logger.info("")
    
    # 显示选中的文件（前10个）
    logger.info("选中的文件示例（前10个）:")
    for i, f in enumerate(selected_files[:10], 1):
        package_name = f.parent.name
        logger.info(f"  {i}. {package_name}")
    if len(selected_files) > 10:
        logger.info(f"  ... 还有 {len(selected_files) - 10} 个文件")
    
    # 创建临时目录，复制选中的文件
    temp_dir = Path(tempfile.mkdtemp(prefix="kb_build_"))
    logger.info(f"\n临时目录: {temp_dir}")
    
    try:
        # 检查是否存在已有知识库
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
        
        # 过滤出新文件（跳过已处理的）
        new_files = [f for f in selected_files if f.parent.name not in existing_packages]
        skipped_count = len(selected_files) - len(new_files)
        
        if skipped_count > 0:
            logger.info(f"✅ 跳过 {skipped_count} 个已处理的包")
        if len(new_files) == 0:
            logger.info("✅ 所有文件都已处理，无需重新构建！")
            return
        
        logger.info(f"📝 需要处理 {len(new_files)} 个新包")
        
        # 根据NUM_WORKERS选择处理方式
        if NUM_WORKERS > 1:
            # 多进程并行处理
            logger.info(f"\n⚡ 使用 {NUM_WORKERS} 进程并行处理文件...")
            
            with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
                # 提交所有任务
                future_to_file = {
                    executor.submit(process_single_verify_json, str(f)): f 
                    for f in new_files
                }
                
                # 收集结果并复制到临时目录
                with tqdm(total=len(new_files), desc="处理文件") as pbar:
                    for future in as_completed(future_to_file):
                        result = future.result()
                        
                        if result is not None:
                            # 复制到临时目录
                            target_dir = temp_dir / result['kb_id']
                            target_dir.mkdir(parents=True, exist_ok=True)
                            
                            # 保存处理后的数据
                            with open(target_dir / "verify.json", 'w', encoding='utf-8') as f:
                                json.dump(result['data'], f, ensure_ascii=False, indent=2)
                        
                        pbar.update(1)
        else:
            # 单进程处理（原来的方式）
            logger.info("\n📋 使用单进程处理文件...")
            for verify_file in tqdm(new_files, desc="复制文件"):
                package_name = verify_file.parent.name
                target_dir = temp_dir / package_name
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(verify_file, target_dir / "verify.json")
        
        # 创建知识库对象
        logger.info("\n🔧 初始化知识库...")
        kb = RAGKnowledgeBase(kb_path=str(kb_path))
        
        # 构建知识库
        logger.info("\n🚀 开始提取恶意代码片段并生成embeddings...")
        logger.info("这可能需要几分钟时间，请耐心等待...\n")
        
        kb.build_from_verify_jsons(str(temp_dir))
        
        # 打印统计信息
        logger.info("\n" + "=" * 80)
        logger.info("✅ 知识库构建完成！")
        logger.info("=" * 80)
        logger.info(f"📊 统计信息:")
        logger.info(f"  - 使用的包数量: {len(selected_files)}")
        logger.info(f"  - 总包数: {len(kb.packages)}")
        
        # 统计总代码片段数
        total_snippets = sum(len(pkg.get('malicious_snippets', [])) for pkg in kb.packages)
        logger.info(f"  - 总代码片段数: {total_snippets}")
        logger.info(f"  - 代码embeddings形状: {kb.code_embeddings.shape if kb.code_embeddings is not None else 'None'}")
        logger.info(f"  - 行为embeddings形状: {kb.behavior_embeddings.shape if kb.behavior_embeddings is not None else 'None'}")
        
        # 展示几个示例包
        logger.info("\n📝 示例包信息:")
        for i, pkg in enumerate(kb.packages[:3], 1):
            logger.info(f"\n--- 包 {i} ---")
            logger.info(f"ID: {pkg['kb_id']}")
            logger.info(f"包名: {pkg.get('package_info', {}).get('package_name', 'N/A')}")
            logger.info(f"代码片段数: {len(pkg.get('malicious_snippets', []))}")
            if pkg.get('malicious_snippets'):
                snippet = pkg['malicious_snippets'][0]
                logger.info(f"首个片段代码: {snippet.get('code', '')[:100]}...")
        
        # 保存位置
        logger.info(f"\n💾 知识库文件已保存到:")
        logger.info(f"  - {kb_path / 'knowledge_base.json'}")
        logger.info(f"  - {kb_path / 'code_embeddings.npy'}")
        logger.info(f"  - {kb_path / 'behavior_embeddings.npy'}")
        
        logger.info("\n✅ 知识库构建成功！现在可以用于恶意代码检测。")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"\n❌ 知识库构建失败: {e}", exc_info=True)
        return
    
    finally:
        # 清理临时目录
        logger.info(f"\n🧹 清理临时目录: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    # 设置随机种子以便复现
    random.seed(42)
    main()