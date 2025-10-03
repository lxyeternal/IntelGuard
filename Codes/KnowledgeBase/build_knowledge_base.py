"""
构建RAG知识库

从verify.json文件中提取恶意代码片段，生成知识库
支持通过MAX_SAMPLES参数控制使用的样本数量
"""

import sys
from pathlib import Path
import random
import tempfile
import shutil

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.KnowledgeBase.rag_detector import RAGKnowledgeBase
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ 配置参数 ============
# 最大样本数量 (设为None则使用全部样本)
MAX_SAMPLES = 50  # 修改这个值来控制样本数量，例如: 50, 100, None(全部)
# =================================


def main():
    """构建知识库主函数"""
    
    # 配置路径
    intelli_json_dir = project_root / "Dataset" / "IntelliJson"
    kb_path = project_root / "KnowledgeBase"
    
    # 创建知识库目录
    kb_path.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 80)
    if MAX_SAMPLES:
        logger.info(f"📚 构建RAG知识库（最多 {MAX_SAMPLES} 个样本）")
    else:
        logger.info("📚 构建RAG知识库（使用全部样本）")
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
        # 复制选中的文件到临时目录
        for verify_file in selected_files:
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

