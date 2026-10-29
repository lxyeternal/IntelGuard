"""
RAG-based Malware Detection System

核心思路：
1. 代码切片（基于敏感API）
2. 生成行为Summary
3. 双路检索（代码相似度 + 行为相似度）
4. LLM增强分析
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
from dataclasses import dataclass
import numpy as np

# 注意：RAGMalwareDetector 不需要导入 LLMCodeSlicer
# 代码切片由上层 PackageMalwareDetector 完成
# RAGMalwareDetector 只负责检测已切片的代码

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CodeSlice:
    """代码切片数据结构"""
    slice_id: str
    code: str
    behavior_summary: str
    file_path: str
    sensitive_apis: List[str]


@dataclass
class KnowledgeMatch:
    """知识库匹配结果"""
    match_id: str
    source_package: str
    source_file: str
    matched_snippet: Dict[str, Any]
    similarity_score: float
    match_type: str  # 'code', 'behavior', or 'combined'
    code_similarity: float = 0.0  # 代码相似度（可选）
    behavior_similarity: float = 0.0  # 行为相似度（可选）
    cluster_info: Optional[Dict[str, Any]] = None  # 所属行为簇，无聚类时为 None


class RAGKnowledgeBase:
    """RAG知识库管理（重构版：保持verify.json结构）"""
    
    def __init__(self, kb_path: str):
        self.kb_path = Path(kb_path)
        
        # 新结构：包级别存储
        self.packages = []  # 包列表（保持原始结构）
        self.packages_dict = {}  # 包ID -> 包数据（用于快速查找）
        self.snippet_index = {}  # 片段索引 -> (包ID, 片段在包中的索引)
        
        # Embedding仍然是片段级别
        self.code_embeddings = None
        self.behavior_embeddings = None
        # 聚类结果，可选
        self.clusters = None
        self.cluster_centroids = None
        self.snippet_behavior_cluster = None
        
        # 延迟初始化（只在需要时初始化）
        self.llm_agent = None
        self.embedding_model = None
        self._llm_initialized = False
    
    def _init_embedding_model(self):
        """延迟初始化embedding模型（只在需要时初始化）"""
        if self._llm_initialized:
            return
        
        logger.info("🔧 初始化Embedding模型...")
        try:
            import sys
            from pathlib import Path
            project_root = str(Path(__file__).parent.parent.parent)
            sys.path.insert(0, project_root)
            
            from Codes.GPTAnalysis.llmquery import LLMAgent
            self.llm_agent = LLMAgent()
            self.embedding_model = self.llm_agent.embedding_model
            logger.info(f"✅ 使用LLMAgent (模型: {self.embedding_model})")
        except Exception as e:
            logger.warning(f"⚠️ LLMAgent初始化失败: {e}，将使用mock embeddings")
            self.llm_agent = None
        
        self._llm_initialized = True
    
    def build_from_verify_jsons(self, intelli_json_dir: str, incremental: bool = True):
        """
        从所有verify.json构建知识库（逐个处理并保存）
        
        Args:
            intelli_json_dir: verify.json文件目录
            incremental: 是否增量构建（合并到已有知识库）
        """
        logger.info(f"Building knowledge base from {intelli_json_dir}")
        
        # 如果是增量构建，先尝试加载已有知识库
        if incremental:
            try:
                self.load_kb()
                logger.info(f"📦 加载已有知识库: {len(self.packages)} 个包")
            except FileNotFoundError:
                logger.info("📦 未找到已有知识库，将从头构建")
        
        # 初始化embedding模型（只初始化一次）
        self._init_embedding_model()
        
        verify_files = list(Path(intelli_json_dir).rglob("verify.json"))
        logger.info(f"Found {len(verify_files)} verify.json files")
        
        # 获取已有包ID集合
        existing_kb_ids = {pkg['kb_id'] for pkg in self.packages}
        
        snippet_count = len(self.snippet_index)  # 从已有的片段数量开始计数
        new_packages_count = 0
        
        # 逐个处理每个verify.json
        for idx, verify_file in enumerate(verify_files, 1):
            try:
                kb_id = verify_file.parent.name
                
                # 跳过已存在的包
                if kb_id in existing_kb_ids:
                    logger.debug(f"Skipping existing package: {kb_id}")
                    continue
                
                logger.info(f"📦 处理 [{idx}/{len(verify_files)}] {kb_id}")
                
                with open(verify_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 处理 package_info 可能是对象或数组的情况
                package_info = data.get('package_info', {})
                if isinstance(package_info, list):
                    package_info = package_info[0] if package_info else {}
                
                # 构建包条目（保持原始verify.json结构）
                package_entry = {
                    'kb_id': kb_id,
                    'source_file': str(verify_file),
                    'package_info': package_info,
                    'malicious_snippets': data.get('malicious_snippets', []),
                    'attack_chain': data.get('attack_chain', []),
                    'detection_knowledge': data.get('detection_knowledge', {})
                }
                
                # 提取这个包的代码片段和行为
                codes = []
                behaviors = []
                for snippet in package_entry['malicious_snippets']:
                    codes.append(snippet.get('code_snippet', ''))
                    behaviors.append(snippet.get('code_behavior', ''))
                
                # 为这个包生成embeddings
                if codes:
                    logger.info(f"   生成 {len(codes)} 个代码片段的embeddings...")
                    new_code_embeddings = self._batch_embed(codes, prefix="Code: ")
                    new_behavior_embeddings = self._batch_embed(behaviors, prefix="Behavior: ")
                    
                    # 合并到已有的embeddings
                    if self.code_embeddings is not None and len(self.code_embeddings) > 0:
                        self.code_embeddings = np.vstack([self.code_embeddings, new_code_embeddings])
                        self.behavior_embeddings = np.vstack([self.behavior_embeddings, new_behavior_embeddings])
                    else:
                        self.code_embeddings = new_code_embeddings
                        self.behavior_embeddings = new_behavior_embeddings
                
                # 为每个片段建立索引
                for snippet_idx in range(len(package_entry['malicious_snippets'])):
                    self.snippet_index[snippet_count] = (package_entry['kb_id'], snippet_idx)
                    snippet_count += 1
                
                # 添加到包列表
                self.packages.append(package_entry)
                
                # 更新packages_dict
                self.packages_dict[kb_id] = package_entry
                
                # 更新已有包ID集合
                existing_kb_ids.add(kb_id)
                
                new_packages_count += 1
                
                # ✅ 关键：每处理完一个包就立即保存！
                self._save_kb()
                logger.info(f"   ✅ 已保存到知识库（共 {len(self.packages)} 个包，{snippet_count} 个片段）")
            
            except Exception as e:
                logger.error(f"Error processing {verify_file}: {e}")
                import traceback
                traceback.print_exc()
        
        if new_packages_count > 0:
            logger.info(f"\n🎉 处理完成！新增 {new_packages_count} 个包，总计 {len(self.packages)} 个包，{snippet_count} 个片段")
        else:
            logger.info(f"\n✅ 没有新包需要添加，知识库已是最新（共 {len(self.packages)} 个包）")
    
    def _generate_embeddings(self):
        """为所有片段生成embeddings（片段级别）"""
        logger.info("Generating embeddings...")
        
        # 确保embedding模型已初始化
        self._init_embedding_model()
        
        # 遍历所有包的所有片段
        codes = []
        behaviors = []
        
        for package in self.packages:
            for snippet in package['malicious_snippets']:
                codes.append(snippet.get('code_snippet', ''))
                behaviors.append(snippet.get('code_behavior', ''))
        
        self.code_embeddings = self._batch_embed(codes, prefix="Code: ")
        self.behavior_embeddings = self._batch_embed(behaviors, prefix="Behavior: ")
        
        logger.info(f"Generated {len(self.code_embeddings)} embeddings")
    
    def _generate_embeddings_incremental(self, new_packages_count: int):
        """
        增量生成embeddings（仅为新增的包生成）
        
        Args:
            new_packages_count: 新增的包数量
        """
        logger.info(f"🚀 增量生成embeddings（仅处理新增的 {new_packages_count} 个包）...")
        
        # 确保embedding模型已初始化
        self._init_embedding_model()
        
        # 提取新包的代码和行为
        new_codes = []
        new_behaviors = []
        
        # 只处理最后新增的包
        for package in self.packages[-new_packages_count:]:
            for snippet in package['malicious_snippets']:
                new_codes.append(snippet.get('code_snippet', ''))
                new_behaviors.append(snippet.get('code_behavior', ''))
        
        logger.info(f"   需要生成 {len(new_codes)} 个新embeddings")
        
        # 生成新的embeddings
        new_code_embeddings = self._batch_embed(new_codes, prefix="Code: ")
        new_behavior_embeddings = self._batch_embed(new_behaviors, prefix="Behavior: ")
        
        # 合并到已有的embeddings
        if self.code_embeddings is not None and len(self.code_embeddings) > 0:
            self.code_embeddings = np.vstack([self.code_embeddings, new_code_embeddings])
            self.behavior_embeddings = np.vstack([self.behavior_embeddings, new_behavior_embeddings])
            logger.info(f"✅ 合并embeddings: 原有 {len(self.code_embeddings) - len(new_code_embeddings)} + 新增 {len(new_code_embeddings)} = 总计 {len(self.code_embeddings)}")
        else:
            self.code_embeddings = new_code_embeddings
            self.behavior_embeddings = new_behavior_embeddings
            logger.info(f"✅ 首次生成embeddings: {len(self.code_embeddings)} 个")
    
    def _batch_embed(self, texts: List[str], prefix: str = "", batch_size: int = 100) -> np.ndarray:
        """批量生成embeddings"""
        if self.llm_agent is None:
            # Mock embeddings for testing
            return np.random.rand(len(texts), 3072)
        
        embeddings = []
        for i, text in enumerate(texts):
            if i % 10 == 0:
                logger.info(f"Generating embedding {i+1}/{len(texts)}")
            
            try:
                # 使用LLMAgent的generate_embedding方法
                embedding = self.llm_agent.generate_embedding(prefix + text)
                embeddings.append(embedding)
            except Exception as e:
                logger.error(f"Embedding error for text {i}: {e}")
                # Fallback to zero vector
                embeddings.append(np.zeros(self.llm_agent.dimension))
        
        return np.array(embeddings)
    
    def _embed_single(self, text: str, prefix: str = "") -> np.ndarray:
        """生成单个文本的 embedding，失败重试，不返回 None。"""
        last_err = None
        for attempt in range(3):
            try:
                emb = self._embed_single_once(text, prefix)
                if emb is not None and np.asarray(emb).ndim == 1 and float(np.abs(emb).sum()) > 0:
                    return np.asarray(emb, dtype=np.float32)
                last_err = "empty embedding"
            except Exception as e:
                last_err = e
            import time as _t
            _t.sleep(2 * (attempt + 1))
        raise RuntimeError(f"embedding failed after retries: {last_err}")

    def _embed_single_once(self, text: str, prefix: str = "") -> np.ndarray:
        """生成单个文本的embedding"""
        if self.llm_agent is None:
            return np.random.rand(3072)
        
        try:
            # 使用LLMAgent的generate_embedding方法
            embedding = self.llm_agent.generate_embedding(prefix + text)
            return embedding
        except Exception as e:
            logger.error(f"Embedding error: {e}")
            return np.zeros(self.llm_agent.dimension)
    
    def retrieve_similar(
        self, 
        query_code: str, 
        query_behavior: str, 
        top_k: int = 5,
        code_weight: float = 0.5,
        behavior_weight: float = 0.5
    ) -> List[KnowledgeMatch]:
        """
        双路检索：代码相似度 + 行为相似度（重构版）
        
        Args:
            query_code: 查询的代码片段
            query_behavior: 查询的行为描述
            top_k: 返回前K个结果
            code_weight: 代码相似度权重
            behavior_weight: 行为相似度权重
        """
        # 确保embedding模型已初始化
        self._init_embedding_model()
        
        # 1. 生成查询embeddings
        code_emb = self._embed_single(query_code, prefix="Code: ")
        behavior_emb = self._embed_single(query_behavior, prefix="Behavior: ")
        
        # 2. 计算相似度（片段级别）
        code_similarities = self._cosine_similarity(code_emb, self.code_embeddings)
        behavior_similarities = self._cosine_similarity(behavior_emb, self.behavior_embeddings)
        
        # 3. 加权融合
        combined_scores = (
            code_weight * code_similarities + 
            behavior_weight * behavior_similarities
        )
        
        # 4. 获取Top-K片段索引
        #    有聚类时先按行为簇质心锚定，再在簇内按融合分排序
        if self.clusters is not None and len(self.cluster_centroids) > 0:
            top_indices = self._cluster_anchored_topk(behavior_emb, combined_scores, top_k)
        else:
            top_indices = np.argsort(combined_scores)[::-1][:top_k]
        
        # 5. 通过片段索引查找对应的包和片段
        matches = []
        for snippet_idx in top_indices:
            snippet_idx = int(snippet_idx)
            
            # 通过snippet_index找到对应的包和片段
            pkg_id, snippet_idx_in_pkg = self.snippet_index[snippet_idx]
            
            # 从packages_dict查找包（O(1)查找）
            package = self.packages_dict[pkg_id]
            
            # 获取片段
            snippet = package['malicious_snippets'][snippet_idx_in_pkg]
            
            # 构建完整的matched_snippet（包含包信息和片段信息）
            matched_snippet = {
                # 片段信息
                'snippet_id': snippet.get('snippet_id', ''),
                'code_snippet': snippet.get('code_snippet', ''),
                'code_behavior': snippet.get('code_behavior', ''),
                'malice_analysis': snippet.get('malice_analysis', {}),
                'execution_context': snippet.get('execution_context', {}),
                
                # 包信息（引用，不重复）
                'package_name': package['package_info'].get('package_name', 'unknown'),
                'package_manager': package['package_info'].get('package_manager', 'unknown'),
                'package_versions': package['package_info'].get('package_versions', ''),
                'why_malicious': package['package_info'].get('why_malicious', ''),
                
                # 包级别知识（引用，不重复）
                'attack_chain': package['attack_chain'],
                'detection_knowledge': package['detection_knowledge']
            }
            
            match = KnowledgeMatch(
                match_id=f"{pkg_id}_{snippet.get('snippet_id', '')}",
                source_package=f"{package['package_info'].get('package_name', 'unknown')} ({package['package_info'].get('package_manager', 'unknown')})",
                source_file=package.get('source_file', 'unknown'),  # 使用.get()防止KeyError
                matched_snippet=matched_snippet,
                similarity_score=float(combined_scores[snippet_idx]),
                match_type='combined',
                code_similarity=float(code_similarities[snippet_idx]),
                behavior_similarity=float(behavior_similarities[snippet_idx]),
                cluster_info=self.cluster_info_for(snippet_idx)
            )
            matches.append(match)
        
        return matches

    def _cluster_anchored_topk(self, behavior_emb: np.ndarray, combined_scores: np.ndarray, top_k: int,
                               n_anchor_clusters: int = 3, max_per_cluster: int = 2) -> List[int]:
        """簇锚定检索：先选 top 簇，再按分数取片段，每簇最多 max_per_cluster 条。"""
        q = behavior_emb / (np.linalg.norm(behavior_emb) + 1e-10)
        cent_sims = self.cluster_centroids @ q
        anchor = np.argsort(cent_sims)[::-1][:n_anchor_clusters]
        anchor_ids = {self.clusters["behavior"][int(a)]["id"] for a in anchor}
        labels = self.snippet_behavior_cluster
        cand = set(np.where(np.isin(labels, list(anchor_ids)))[0].tolist())
        cand.update(np.argsort(combined_scores)[::-1][: max(2 * top_k, 10)].tolist())
        ranked = sorted(cand, key=lambda i: -combined_scores[i])
        chosen, per_cluster = [], {}
        for i in ranked:
            c = int(labels[i])
            if c >= 0 and per_cluster.get(c, 0) >= max_per_cluster:
                continue
            chosen.append(int(i))
            per_cluster[c] = per_cluster.get(c, 0) + 1
            if len(chosen) >= top_k:
                break
        if len(chosen) < top_k:   # fill from the global ranking if the cap was too strict
            for i in np.argsort(combined_scores)[::-1]:
                if int(i) not in chosen:
                    chosen.append(int(i))
                if len(chosen) >= top_k:
                    break
        return chosen
    
    @staticmethod
    def _cosine_similarity(query: np.ndarray, corpus: np.ndarray) -> np.ndarray:
        """计算余弦相似度"""
        query = query / (np.linalg.norm(query) + 1e-10)
        corpus = corpus / (np.linalg.norm(corpus, axis=1, keepdims=True) + 1e-10)
        return np.dot(corpus, query)
    
    def _save_kb(self):
        """保存知识库（新结构）"""
        kb_file = self.kb_path / "knowledge_base.json"
        kb_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 保存JSON（包含完整的包结构）
        with open(kb_file, 'w', encoding='utf-8') as f:
            json.dump({
                'packages': self.packages,
                'metadata': {
                    'total_packages': len(self.packages),
                    'total_snippets': len(self.snippet_index),
                    'snippet_index': {str(k): v for k, v in self.snippet_index.items()}  # JSON需要字符串key
                }
            }, f, indent=2, ensure_ascii=False)
        
        # 保存embeddings（片段级别）
        if self.code_embeddings is not None:
            np.save(self.kb_path / "snippet_code_embeddings.npy", self.code_embeddings)
            np.save(self.kb_path / "snippet_behavior_embeddings.npy", self.behavior_embeddings)
        
        logger.info(f"Knowledge base saved to {kb_file}")
    
    def load_kb(self):
        """加载已有的知识库（新结构，优化版）"""
        kb_file = self.kb_path / "knowledge_base.json"
        
        if not kb_file.exists():
            raise FileNotFoundError(f"Knowledge base not found at {kb_file}")
        
        with open(kb_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 加载包列表
        self.packages = data['packages']
        
        # 转换为dict以提高查询性能（O(1)查找）
        self.packages_dict = {
            pkg['kb_id']: pkg 
            for pkg in self.packages
        }
        
        # 加载snippet索引（转换key为int）
        self.snippet_index = {
            int(k): tuple(v) 
            for k, v in data['metadata']['snippet_index'].items()
        }
        
        # 加载embeddings
        code_emb_file = self.kb_path / "snippet_code_embeddings.npy"
        behavior_emb_file = self.kb_path / "snippet_behavior_embeddings.npy"
        
        if code_emb_file.exists():
            self.code_embeddings = np.load(code_emb_file)
            self.behavior_embeddings = np.load(behavior_emb_file)
        
        self._load_clusters()
        logger.info(
            f"Loaded knowledge base: {len(self.packages)} packages, "
            f"{len(self.snippet_index)} snippets, "
            f"{len(self.clusters['behavior']) if self.clusters else 0} behavior clusters"
        )

    def _load_clusters(self):
        cf = self.kb_path / "clusters.json"
        cc = self.kb_path / "behavior_cluster_centroids.npy"
        self.clusters = None
        if cf.exists() and cc.exists():
            try:
                with open(cf, 'r', encoding='utf-8') as f:
                    clusters = json.load(f)
                if clusters.get("n_snippets") != len(self.snippet_index):
                    logger.warning("clusters.json is stale (snippet count differs); run cluster_knowledge.py")
                    return
                self.clusters = clusters
                self.cluster_centroids = np.load(cc)
                self.snippet_behavior_cluster = np.array(clusters["snippet_behavior_cluster"])
                self.cluster_by_id = {c["id"]: c for c in clusters["behavior"]}
            except Exception as e:
                logger.warning(f"failed to load clusters: {e}")
                self.clusters = None

    def cluster_summary(self) -> Dict[str, Any]:
        if not self.clusters:
            return {}
        return {"behavior_clusters": len(self.clusters["behavior"]), "code_clusters": len(self.clusters["code"]),
                "params": self.clusters["params"]}

    def cluster_info_for(self, snippet_idx: int) -> Optional[Dict[str, Any]]:
        if self.clusters is None or self.snippet_behavior_cluster is None:
            return None
        cid = int(self.snippet_behavior_cluster[snippet_idx])
        if cid < 0:
            return {"behavior_cluster": -1, "size": 1, "unified_explanation": "(unclustered / noise)"}
        c = self.cluster_by_id[cid]
        return {"behavior_cluster": cid, "size": c["size"], "n_packages": c["n_packages"],
                "predicates": c["predicates"], "unified_explanation": c["unified_explanation"],
                "representative_behavior": c["representative_behavior"], "top_triggers": c["top_triggers"]}


class RAGMalwareDetector:
    """基于RAG的恶意软件检测器"""
    
    def __init__(
        self, 
        knowledge_base: RAGKnowledgeBase,
        llm_agent=None,
        similarity_threshold: Optional[float] = None
    ):
        """
        初始化RAG检测器
        
        Args:
            knowledge_base: RAG知识库
            llm_agent: LLM代理
            similarity_threshold: 相似度阈值过滤
                - None: 不过滤，所有检索结果都传给LLM（默认）
                - float (如0.5): 只传相似度 >= 该阈值的结果
                - 如果所有结果都 < 阈值，会告知LLM依靠自身知识判断
        """
        self.kb = knowledge_base
        # 注意：不需要 code_slicer，代码切片由上层 PackageMalwareDetector 完成
        # RAGMalwareDetector 只负测已切片的代码
        self.llm_agent = llm_agent
        self.similarity_threshold = similarity_threshold
        self.detection_prompt = self._load_detection_prompt()
    
    def _load_detection_prompt(self) -> str:
        """加载RAG检测提示词模板"""
        prompt_path = Path(__file__).parent / "rag_detection_prompt.txt"
        
        if prompt_path.exists():
            return prompt_path.read_text(encoding='utf-8')
        else:
            logger.warning(
                f"Detection prompt file not found at {prompt_path}. "
                "Using fallback prompt."
            )
            # 提供一个简单的fallback
            return """Analyze if the following code is malicious.

Code:
```
{code}
```

Behavior: {behavior_summary}

Similar patterns:
{knowledge_context}

Output JSON:
{{
  "is_malicious": "yes/no",
  "confidence": 0.0-1.0,
  "malicious_behavior": "description or 'none'",
  "reasoning": "explanation",
  "evidence": ["evidence1", "evidence2"],
  "matched_patterns": ["pattern1"]
}}"""
    
    def detect_package(self, package_path: str) -> Dict[str, Any]:
        """
        【废弃方法】检测整个包
        
        注意：此方法已废弃！请使用 PackageMalwareDetector.detect_package() 代替。
        RAGMalwareDetector 只负责检测已切片的代码，不负责代码切片。
        
        保留此方法仅为向后兼容，不应在新代码中使用。
        """
        logger.warning(
            "⚠️  detect_package() 方法已废弃！"
            "请使用 PackageMalwareDetector.detect_package() 代替。"
        )
        return {"error": "此方法已废弃，请使用 PackageMalwareDetector.detect_package()"}
    
    def _detect_slice(
        self, 
        code: str, 
        behavior_summary: str,
        file_path: str, 
        slice_id: str
    ) -> Dict[str, Any]:
        """
        【废弃方法】检测单个代码切片
        
        注意：此方法已废弃！请使用 detect() 方法代替。
        此方法返回的格式与 detect() 不同，不应在新代码中使用。
        """
        logger.warning("⚠️  _detect_slice() 方法已废弃！请使用 detect() 方法代替。")
        return {"error": "此方法已废弃"}
    
    def _generate_behavior_summary(self, code: str) -> str:
        """生成代码行为summary"""
        if self.llm_agent is None:
            return "Behavior summary not available (no LLM agent)"
        
        prompt = f"""Analyze the following code snippet and provide a concise behavior summary (1-2 sentences).

Focus on:
- What sensitive operations it performs
- What data it accesses
- What network/file/process activities it initiates

Code:
```
{code}
```

Provide ONLY the behavior summary, no additional text."""

        try:
            # 使用LLMAgent的perform_query方法
            messages = [{"role": "user", "content": prompt}]
            response = self.llm_agent.perform_query(messages, extract_json=False)
            return response.strip()
        except Exception as e:
            logger.error(f"Error generating behavior summary: {e}")
            return "Error generating summary"
    
    def _llm_enhanced_analysis(
        self, 
        code: str, 
        behavior: str, 
        similar_matches: List[KnowledgeMatch],
        no_match_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        LLM增强分析（使用提示词模板）
        
        关键：将检索到的malice_analysis和示例代码作为上下文
        
        Args:
            code: 代码片段
            behavior: 行为描述
            similar_matches: RAG检索到的相似匹配
            no_match_reason: 无匹配的原因（如果提供，表示需要LLM依靠自身知识）
        """
        if self.llm_agent is None:
            return {
                'is_suspicious': False,
                'is_malicious': 'no',
                'confidence': 0.0,
                'reasoning': 'No LLM agent available',
                'evidence': [],
                'malicious_behavior': 'none',
                'matched_patterns': []
            }
        
        # 构建知识库上下文
        if not similar_matches:
            if no_match_reason:
                # 有原因说明（被阈值过滤了），提示LLM依靠自身知识
                knowledge_context = f"""
**Note:** {no_match_reason}

Please analyze the code based on your own knowledge of malicious code patterns, 
common attack techniques, and security best practices.
"""
            else:
                # 原始就没有匹配
                return {
                    'is_suspicious': False,
                    'is_malicious': 'no',
                    'confidence': 0.0,
                    'reasoning': 'No similar patterns in knowledge base',
                    'evidence': [],
                    'malicious_behavior': 'none',
                    'matched_patterns': []
                }
        else:
            # 有匹配，构建上下文
            knowledge_context = self._build_analysis_context(similar_matches)
        
        # 使用模板文件填充变量
        prompt = self.detection_prompt.format(
            code=code,
            behavior_summary=behavior,
            num_matches=len(similar_matches),
            knowledge_context=knowledge_context
        )

        try:
            # 使用LLMAgent的perform_query方法
            messages = [{"role": "user", "content": prompt}]
            response = self.llm_agent.perform_query(messages, extract_json=True)
            
            # 解析JSON响应（新格式）
            result = self._parse_llm_response(response)
            return result
        
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reasoning': f'Analysis error: {e}',
                'evidence': [],
                'malicious_behavior': 'none',
                'matched_patterns': []
            }
    
    def _build_analysis_context(self, matches: List[KnowledgeMatch]) -> str:
        """构建分析上下文（从检索结果）"""
        context_parts = []
        
        for i, match in enumerate(matches[:3], 1):  # 只取前3个最相似的
            snippet = match.matched_snippet
            malice = snippet.get('malice_analysis', {})
            
            # 构建包标识（包含包管理器）
            package_name = snippet.get('package_name', '')
            package_manager = snippet.get('package_manager', '')
            package_identifier = f"{package_name} ({package_manager})" if package_manager else package_name
            
            context_parts.append(f"""
                ### Example {i} (Similarity: {match.similarity_score:.2f})
                **Source Package:** {package_identifier}

                **Code:**
                ```
                {snippet.get('code_snippet', '')[:500]}...
                ```

                **Behavior:** {snippet.get('code_behavior', '')}

                **Why Suspicious:** {malice.get('why_suspicious', '')}

                **Key Indicators:**
                {chr(10).join('- ' + ind for ind in malice.get('key_indicators', []))}
                {self._cluster_context(match)}
                """)
        
        return "\n".join(context_parts)

    @staticmethod
    def _cluster_context(match: KnowledgeMatch) -> str:
        """行为簇级别的统一解释，拼进提示词。"""
        ci = match.cluster_info
        if not ci or ci.get("behavior_cluster", -1) < 0:
            return ""
        return (f"**Behavior Concept (cluster of {ci.get('size')} known-malicious snippets from "
                f"{ci.get('n_packages')} reports):** {ci.get('unified_explanation')}. "
                f"Typical trigger(s): {', '.join(ci.get('top_triggers', {}).keys()) or 'n/a'}.")
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析LLM响应（支持新的JSON格式）"""
        # 尝试提取JSON
        import re
        
        # 尝试找到JSON block
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = response
        
        try:
            result = json.loads(json_str)
            
            # 转换新格式到旧格式（保持向后兼容）
            # 新格式: is_malicious (yes/no), malicious_behavior, matched_patterns
            # 旧格式: is_suspicious (bool)
            if 'is_malicious' in result:
                # 转换 yes/no 为 boolean
                is_malicious_str = str(result.get('is_malicious', 'no')).lower()
                result['is_suspicious'] = is_malicious_str in ['yes', 'true', '1']
            
            # 确保所有必需字段存在
            result.setdefault('confidence', 0.0)
            result.setdefault('reasoning', '')
            result.setdefault('evidence', [])
            result.setdefault('malicious_behavior', 'none')
            result.setdefault('matched_patterns', [])
            
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}\nResponse: {response[:200]}")
            # 降级处理
            return {
                'is_suspicious': False,
                'is_malicious': 'no',
                'confidence': 0.0,
                'reasoning': 'Failed to parse LLM response',
                'evidence': [],
                'malicious_behavior': 'none',
                'matched_patterns': [],
                'raw_response': response
            }
    
    def _summarize_detection(self, detection_results: List[Dict]) -> Dict[str, Any]:
        """汇总检测结果"""
        suspicious_count = sum(1 for r in detection_results if r['is_suspicious'])
        
        avg_confidence = (
            sum(r['confidence'] for r in detection_results if r['is_suspicious']) / 
            max(suspicious_count, 1)
        )
        
        return {
            'total_slices': len(detection_results),
            'suspicious_slices': suspicious_count,
            'average_confidence': avg_confidence,
            'is_package_malicious': suspicious_count > 0 and avg_confidence > 0.6
        }
    
    def detect(
        self, 
        code_snippet: str, 
        code_behavior: str
    ) -> 'DetectionResult':
        """
        RAG + LLM 检测接口
        
        流程：
        1. RAG检索相似的恶意模式
        2. 根据similarity_threshold过滤结果
        3. LLM分析代码是否恶意
        4. 只依赖LLM的is_malicious判断（yes/no）
        
        Args:
            code_snippet: 代码片段
            code_behavior: 代码行为描述
        
        Returns:
            DetectionResult对象
        """
        # 1. RAG检索相似知识
        similar_matches = self.kb.retrieve_similar(
            query_code=code_snippet,
            query_behavior=code_behavior,
            top_k=5
        )
        
        # 2. 根据相似度阈值过滤结果
        filtered_matches = similar_matches
        original_count = len(similar_matches)
        
        if self.similarity_threshold is not None and similar_matches:
            # 过滤掉相似度低于阈值的结果
            filtered_matches = [
                m for m in similar_matches 
                if m.similarity_score >= self.similarity_threshold
            ]
            
            if len(filtered_matches) < original_count:
                logger.info(
                    f"Filtered matches: {original_count} -> {len(filtered_matches)} "
                    f"(threshold: {self.similarity_threshold})"
                )
        
        # 3. 如果没有匹配（原始就没有，或过滤后为空）
        if not filtered_matches:
            # 如果是因为阈值过滤导致为空，使用LLM自身知识判断
            if original_count > 0 and self.similarity_threshold is not None:
                logger.info(
                    f"All {original_count} matches below threshold {self.similarity_threshold}, "
                    "relying on LLM's own knowledge"
                )
                # 传递一个特殊标记，让LLM知道需要依靠自身知识
                llm_analysis = self._llm_enhanced_analysis(
                    code=code_snippet,
                    behavior=code_behavior,
                    similar_matches=[],  # 空列表表示无有效匹配
                    no_match_reason=f"No matches above similarity threshold {self.similarity_threshold}"
                )
            else:
                # 原始就没有匹配
                return DetectionResult(
                    is_malicious=False,
                    malice_score=0.0,
                    confidence=1.0,
                    explanation="No similar malicious patterns found in knowledge base, classified as benign code",
                    matched_knowledge=[]
                )
        else:
            # 4. 使用LLM进行增强分析（有有效匹配）
            llm_analysis = self._llm_enhanced_analysis(
                code=code_snippet,
                behavior=code_behavior,
                similar_matches=filtered_matches
            )
        
        # 5. 解析LLM结果
        # 关键：只依赖 is_malicious (yes/no)
        is_malicious_str = str(llm_analysis.get('is_malicious', 'no')).lower()
        is_malicious = is_malicious_str in ['yes', 'true', '1']
        
        # confidence 保留但不用于判断
        confidence = float(llm_analysis.get('confidence', 0.0))
        
        # 计算一个参考分数（基于相似度，但不用于判断）
        # 使用过滤后的匹配计算分数
        if filtered_matches:
            weights = [1.0, 0.8, 0.6, 0.4, 0.2][:len(filtered_matches)]
            weighted_sim = sum(m.similarity_score * w for m, w in zip(filtered_matches, weights))
            malice_score = weighted_sim / sum(weights)
        else:
            malice_score = 0.0
        
        # 生成说明
        reasoning = llm_analysis.get('reasoning', '')
        malicious_behavior = llm_analysis.get('malicious_behavior', 'none')
        
        if is_malicious:
            explanation = f"[LLM Judgment: Malicious] {reasoning}"
            if malicious_behavior != 'none':
                explanation += f" | Malicious Behavior: {malicious_behavior}"
        else:
            explanation = f"[LLM Judgment: Benign] {reasoning}"
        
        # 如果使用了阈值过滤，在说明中注明
        if self.similarity_threshold is not None and original_count > len(filtered_matches):
            explanation += f" | Similarity filter: {original_count} -> {len(filtered_matches)} matches (threshold: {self.similarity_threshold})"
        
        return DetectionResult(
            is_malicious=is_malicious,
            malice_score=malice_score,  # 仅供参考
            confidence=confidence,  # 仅供参考
            explanation=explanation,
            matched_knowledge=filtered_matches  # 使用过滤后的匹配
        )


# ==================== 数据类 ====================

@dataclass
class DetectionResult:
    """检测结果"""
    is_malicious: bool
    malice_score: float
    confidence: float
    matched_knowledge: List[KnowledgeMatch]
    explanation: str


def main():
    """示例使用"""
    # 1. 构建知识库
    kb = RAGKnowledgeBase(kb_path="/home2/wenbo/Documents/IntelliGraph/KnowledgeBase")
    
    # 构建知识库（首次运行）
    # kb.build_from_verify_jsons("/home2/wenbo/Documents/IntelliGraph/Dataset/IntelliJson")
    
    # 或加载已有知识库
    try:
        kb.load_kb()
    except FileNotFoundError:
        logger.info("Building new knowledge base...")
        kb.build_from_verify_jsons("/home2/wenbo/Documents/IntelliGraph/Dataset/IntelliJson")
    
    # 2. 创建检测器
    # detector = RAGMalwareDetector(knowledge_base=kb, llm_agent=your_llm_agent)
    
    # 3. 检测包
    # result = detector.detect_package("/path/to/suspicious/package")
    # print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

