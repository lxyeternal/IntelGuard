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

# 假设这些模块存在
try:
    from code_slice import LLMCodeSlicer
except ImportError:
    print("Warning: code_slice module not found, using mock")

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
        
        # 初始化embedding模型
        self._init_embedding_model()
    
    def _init_embedding_model(self):
        """初始化embedding模型（使用LLMAgent）"""
        try:
            import sys
            from pathlib import Path
            project_root = str(Path(__file__).parent.parent.parent)
            sys.path.insert(0, project_root)
            
            from Codes.GPTAnalysis.llmquery import LLMAgent
            self.llm_agent = LLMAgent()
            self.embedding_model = self.llm_agent.embedding_model
            logger.info(f"Using LLMAgent with embedding model: {self.embedding_model}")
        except Exception as e:
            logger.warning(f"Failed to init LLMAgent: {e}, will use mock embeddings")
            self.llm_agent = None
    
    def build_from_verify_jsons(self, intelli_json_dir: str):
        """从所有verify.json构建知识库（保持原始结构）"""
        logger.info(f"Building knowledge base from {intelli_json_dir}")
        
        verify_files = list(Path(intelli_json_dir).rglob("verify.json"))
        logger.info(f"Found {len(verify_files)} verify.json files")
        
        snippet_count = 0  # 全局片段计数器
        
        for verify_file in verify_files:
            try:
                with open(verify_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 处理 package_info 可能是对象或数组的情况
                package_info = data.get('package_info', {})
                if isinstance(package_info, list):
                    package_info = package_info[0] if package_info else {}
                
                # 构建包条目（保持原始verify.json结构）
                package_entry = {
                    'kb_id': verify_file.parent.name,
                    'source_file': str(verify_file),
                    'package_info': package_info,
                    'malicious_snippets': data.get('malicious_snippets', []),
                    'attack_chain': data.get('attack_chain', []),
                    'detection_knowledge': data.get('detection_knowledge', {})
                }
                
                # 为每个片段建立索引
                for snippet_idx, snippet in enumerate(package_entry['malicious_snippets']):
                    self.snippet_index[snippet_count] = (package_entry['kb_id'], snippet_idx)
                    snippet_count += 1
                
                # 添加到包列表
                self.packages.append(package_entry)
            
            except Exception as e:
                logger.error(f"Error processing {verify_file}: {e}")
        
        logger.info(f"Loaded {len(self.packages)} packages with {snippet_count} snippets")
        
        # 构建packages_dict以提高查询性能
        self.packages_dict = {
            pkg['kb_id']: pkg 
            for pkg in self.packages
        }
        
        # 生成embeddings（片段级别）
        self._generate_embeddings()
        
        # 保存知识库
        self._save_kb()
    
    def _generate_embeddings(self):
        """为所有片段生成embeddings（片段级别）"""
        logger.info("Generating embeddings...")
        
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
                behavior_similarity=float(behavior_similarities[snippet_idx])
            )
            matches.append(match)
        
        return matches
    
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
        
        logger.info(
            f"Loaded knowledge base: {len(self.packages)} packages, "
            f"{len(self.snippet_index)} snippets"
        )


class RAGMalwareDetector:
    """基于RAG的恶意软件检测器"""
    
    def __init__(
        self, 
        knowledge_base: RAGKnowledgeBase,
        llm_agent=None
    ):
        self.kb = knowledge_base
        self.code_slicer = LLMCodeSlicer(llm_agent=llm_agent) if llm_agent else None
        self.llm_agent = llm_agent
    
    def detect_package(self, package_path: str) -> Dict[str, Any]:
        """
        检测整个包
        
        流程：
        1. 代码切片
        2. 为每个切片生成行为summary
        3. RAG检索相似知识
        4. LLM增强分析
        """
        logger.info(f"Detecting package: {package_path}")
        
        # 1. 代码切片
        if self.code_slicer is None:
            logger.warning("No code slicer available, skipping slicing")
            return {"error": "Code slicer not initialized"}
        
        slice_result = self.code_slicer.slice_package(package_path)
        
        if not slice_result.get('files'):
            return {"error": "No files to analyze"}
        
        # 2. 分析每个文件的每个切片
        detection_results = []
        
        for file_result in slice_result['files']:
            if file_result['status'] != 'success':
                continue
            
            file_path = file_result['file_path']
            
            for slice_data in file_result.get('slices', []):
                slice_detection = self._detect_slice(
                    code=slice_data['code'],
                    behavior_summary=slice_data.get('behavior_summary', ''),  # 使用切片时生成的summary
                    file_path=file_path,
                    slice_id=slice_data['slice_id']
                )
                detection_results.append(slice_detection)
        
        # 3. 汇总结果
        summary = self._summarize_detection(detection_results)
        
        return {
            'package_path': package_path,
            'total_slices_analyzed': len(detection_results),
            'malicious_slices': [r for r in detection_results if r['is_suspicious']],
            'summary': summary,
            'details': detection_results
        }
    
    def _detect_slice(
        self, 
        code: str, 
        behavior_summary: str,
        file_path: str, 
        slice_id: str
    ) -> Dict[str, Any]:
        """
        检测单个代码切片
        
        核心步骤：
        1. 使用切片时生成的behavior_summary（避免重复LLM调用）
        2. RAG检索
        3. LLM增强分析
        """
        # 1. 如果没有提供behavior_summary，则生成（降级处理）
        if not behavior_summary:
            behavior_summary = self._generate_behavior_summary(code)
        
        # 2. RAG检索相似知识
        similar_matches = self.kb.retrieve_similar(
            query_code=code,
            query_behavior=behavior_summary,
            top_k=5
        )
        
        # 3. LLM增强分析
        analysis_result = self._llm_enhanced_analysis(
            code=code,
            behavior=behavior_summary,
            similar_matches=similar_matches
        )
        
        return {
            'slice_id': slice_id,
            'file_path': file_path,
            'code': code,
            'behavior_summary': behavior_summary,
            'similar_matches': [
                {
                    # 基本匹配信息
                    'match_id': m.match_id,
                    'source_package': m.source_package,
                    'similarity_score': m.similarity_score,
                    
                    # 片段级别信息
                    'snippet_id': m.matched_snippet.get('snippet_id', ''),
                    'matched_code': m.matched_snippet.get('code_snippet', ''),
                    'matched_behavior': m.matched_snippet.get('code_behavior', ''),
                    'malice_analysis': m.matched_snippet.get('malice_analysis', {}),
                    'execution_context': m.matched_snippet.get('execution_context', {}),
                    
                    # 包级别信息（关键！）
                    'package_info': {
                        'package_name': m.matched_snippet.get('package_name', ''),
                        'package_manager': m.matched_snippet.get('package_manager', ''),
                        'package_versions': m.matched_snippet.get('package_versions', ''),
                        'why_malicious': m.matched_snippet.get('why_malicious', ''),
                    },
                    
                    # 包级别的检测知识
                    'detection_knowledge': m.matched_snippet.get('detection_knowledge', {}),
                    
                    # 包级别的攻击链
                    'attack_chain': m.matched_snippet.get('attack_chain', []),
                }
                for m in similar_matches
            ],
            'is_suspicious': analysis_result['is_suspicious'],
            'confidence': analysis_result['confidence'],
            'reasoning': analysis_result['reasoning'],
            'evidence': analysis_result['evidence']
        }
    
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
        similar_matches: List[KnowledgeMatch]
    ) -> Dict[str, Any]:
        """
        LLM增强分析
        
        关键：将检索到的malice_analysis和示例代码作为上下文
        """
        if self.llm_agent is None or not similar_matches:
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reasoning': 'No LLM agent or no matches',
                'evidence': []
            }
        
        # 构建上下文
        context = self._build_analysis_context(similar_matches)
        
        prompt = f"""You are a security analyst. Analyze whether the following code is malicious.

            **New Code to Analyze:**
            ```
            {code}
            ```

            **Behavior Summary:**
            {behavior}

            **Similar Known Malicious Patterns (from knowledge base):**

            {context}

            **Your Task:**
            1. Compare the new code with the known malicious patterns
            2. Determine if the new code is suspicious or malicious
            3. Provide confidence score (0.0-1.0)
            4. Explain your reasoning with specific evidence

            **Output Format (JSON):**
            {{
            "is_suspicious": true/false,
            "confidence": 0.0-1.0,
            "reasoning": "detailed explanation",
            "evidence": ["evidence 1", "evidence 2", ...]
            }}

            Provide ONLY the JSON output."""

        try:
            # 使用LLMAgent的perform_query方法
            messages = [{"role": "user", "content": prompt}]
            response = self.llm_agent.perform_query(messages, extract_json=True)
            
            # 解析JSON响应
            result = self._parse_llm_response(response)
            return result
        
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reasoning': f'Analysis error: {e}',
                'evidence': []
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
                """)
        
        return "\n".join(context_parts)
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析LLM响应"""
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
            return result
        except json.JSONDecodeError:
            # 降级处理
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reasoning': 'Failed to parse LLM response',
                'evidence': [],
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
        code_behavior: str, 
        malice_threshold: float = 0.5
    ) -> 'DetectionResult':
        """
        简化的检测接口（用于测试）
        
        直接检测给定的代码片段和行为描述，不需要代码切片
        
        Args:
            code_snippet: 代码片段
            code_behavior: 代码行为描述
            malice_threshold: 恶意判定阈值（默认0.5）
        
        Returns:
            DetectionResult对象
        """
        # RAG检索相似知识
        similar_matches = self.kb.retrieve_similar(
            query_code=code_snippet,
            query_behavior=code_behavior,
            top_k=5
        )
        
        # 计算恶意度分数（基于相似度和匹配数量）
        if not similar_matches:
            malice_score = 0.0
            confidence = 1.0
            is_malicious = False
            explanation = "未找到相似的恶意模式"
        else:
            # 恶意度 = 加权相似度（top匹配权重更高）
            weights = [1.0, 0.8, 0.6, 0.4, 0.2][:len(similar_matches)]
            weighted_sim = sum(m.similarity_score * w for m, w in zip(similar_matches, weights))
            malice_score = weighted_sim / sum(weights)
            
            # 置信度基于匹配数量和相似度方差
            confidence = min(len(similar_matches) / 5.0, 1.0)
            if similar_matches:
                similarities = [m.similarity_score for m in similar_matches]
                variance = sum((s - malice_score) ** 2 for s in similarities) / len(similarities)
                confidence *= (1.0 - min(variance, 0.5))  # 方差越小，置信度越高
            
            is_malicious = malice_score >= malice_threshold
            
            # 生成说明
            if is_malicious:
                top_match = similar_matches[0]
                snippet = top_match.matched_snippet
                explanation = (
                    f"检测到与已知恶意包 '{snippet['package_name']}' 的相似模式 "
                    f"(相似度: {top_match.similarity_score:.4f})"
                )
            else:
                explanation = f"相似度较低 (最高: {similar_matches[0].similarity_score:.4f})，可能为正常代码"
        
        return DetectionResult(
            is_malicious=is_malicious,
            malice_score=malice_score,
            confidence=confidence,
            matched_knowledge=similar_matches,
            explanation=explanation
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
    kb = RAGKnowledgeBase(kb_path="/Users/blue/Documents/Github/IntelliGraph/KnowledgeBase")
    
    # 构建知识库（首次运行）
    # kb.build_from_verify_jsons("/Users/blue/Documents/Github/IntelliGraph/Dataset/IntelliJson")
    
    # 或加载已有知识库
    try:
        kb.load_kb()
    except FileNotFoundError:
        logger.info("Building new knowledge base...")
        kb.build_from_verify_jsons("/Users/blue/Documents/Github/IntelliGraph/Dataset/IntelliJson")
    
    # 2. 创建检测器
    # detector = RAGMalwareDetector(knowledge_base=kb, llm_agent=your_llm_agent)
    
    # 3. 检测包
    # result = detector.detect_package("/path/to/suspicious/package")
    # print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

