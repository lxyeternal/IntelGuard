"""RAG knowledge base and the knowledge-guided malware detector."""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
from dataclasses import dataclass
import numpy as np


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CodeSlice:
    """A code slice and its behavior summary."""
    slice_id: str
    code: str
    behavior_summary: str
    file_path: str
    sensitive_apis: List[str]


@dataclass
class KnowledgeMatch:
    """One retrieved knowledge snippet with its scores."""
    match_id: str
    source_package: str
    source_file: str
    matched_snippet: Dict[str, Any]
    similarity_score: float
    match_type: str
    code_similarity: float = 0.0
    behavior_similarity: float = 0.0
    cluster_info: Optional[Dict[str, Any]] = None


class RAGKnowledgeBase:
    """Package-level knowledge base with snippet embeddings and behavior clusters."""
    
    def __init__(self, kb_path: str):
        """Set the knowledge base directory."""
        self.kb_path = Path(kb_path)
        
        self.packages = []
        self.packages_dict = {}
        self.snippet_index = {}
        
        self.code_embeddings = None
        self.behavior_embeddings = None
        self.clusters = None
        self.cluster_centroids = None
        self.snippet_behavior_cluster = None
        
        self.llm_agent = None
        self.embedding_model = None
        self._llm_initialized = False
    
    def _init_embedding_model(self):
        """Create the embedding client on first use."""
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
    
    def build_from_verify_jsons(self, intelli_json_dir: str, merge_existing: bool = True):
        """Add every verify.json under a directory to the knowledge base and save it."""
        logger.info(f"Building knowledge base from {intelli_json_dir}")
        
        if merge_existing:
            try:
                self.load_kb()
                logger.info(f"📦 加载已有知识库: {len(self.packages)} 个包")
            except FileNotFoundError:
                logger.info("📦 未找到已有知识库，将从头构建")
        
        self._init_embedding_model()
        
        verify_files = list(Path(intelli_json_dir).rglob("verify.json"))
        logger.info(f"Found {len(verify_files)} verify.json files")
        
        existing_kb_ids = {pkg['kb_id'] for pkg in self.packages}
        
        snippet_count = len(self.snippet_index)
        new_packages_count = 0
        
        for idx, verify_file in enumerate(verify_files, 1):
            try:
                kb_id = verify_file.parent.name
                
                if kb_id in existing_kb_ids:
                    logger.debug(f"Skipping existing package: {kb_id}")
                    continue
                
                logger.info(f"📦 处理 [{idx}/{len(verify_files)}] {kb_id}")
                
                with open(verify_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                package_info = data.get('package_info', {})
                if isinstance(package_info, list):
                    package_info = package_info[0] if package_info else {}
                
                package_entry = {
                    'kb_id': kb_id,
                    'source_file': str(verify_file),
                    'package_info': package_info,
                    'malicious_snippets': data.get('malicious_snippets', []),
                    'attack_chain': data.get('attack_chain', []),
                    'detection_knowledge': data.get('detection_knowledge', {})
                }
                
                codes = []
                behaviors = []
                for snippet in package_entry['malicious_snippets']:
                    codes.append(snippet.get('code_snippet', ''))
                    behaviors.append(snippet.get('code_behavior', ''))
                
                if codes:
                    logger.info(f"   生成 {len(codes)} 个代码片段的embeddings...")
                    new_code_embeddings = self._batch_embed(codes, prefix="Code: ")
                    new_behavior_embeddings = self._batch_embed(behaviors, prefix="Behavior: ")
                    
                    if self.code_embeddings is not None and len(self.code_embeddings) > 0:
                        self.code_embeddings = np.vstack([self.code_embeddings, new_code_embeddings])
                        self.behavior_embeddings = np.vstack([self.behavior_embeddings, new_behavior_embeddings])
                    else:
                        self.code_embeddings = new_code_embeddings
                        self.behavior_embeddings = new_behavior_embeddings
                
                for snippet_idx in range(len(package_entry['malicious_snippets'])):
                    self.snippet_index[snippet_count] = (package_entry['kb_id'], snippet_idx)
                    snippet_count += 1
                
                self.packages.append(package_entry)
                
                self.packages_dict[kb_id] = package_entry
                
                existing_kb_ids.add(kb_id)
                
                new_packages_count += 1
                
                self._save_kb()
                logger.info(f"   ✅ 已保存到知识库（共 {len(self.packages)} 个包，{snippet_count} 个片段）")
            
            except Exception as e:
                logger.error(f"Error processing {verify_file}: {e}")
                import traceback
                traceback.print_exc()
        
        if new_packages_count > 0:
            logger.info(f"\n🎉 处理完成！共 {len(self.packages)} 个包，{snippet_count} 个片段")
        else:
            logger.info(f"\n✅ 知识库已包含全部报告（共 {len(self.packages)} 个包）")
    
    def _generate_embeddings(self):
        """Embed all snippets."""
        logger.info("Generating embeddings...")
        
        self._init_embedding_model()
        
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
        """Embed a list of texts."""
        if self.llm_agent is None:
            return np.random.rand(len(texts), 3072)
        
        embeddings = []
        for i, text in enumerate(texts):
            if i % 10 == 0:
                logger.info(f"Generating embedding {i+1}/{len(texts)}")
            
            try:
                embedding = self.llm_agent.generate_embedding(prefix + text)
                embeddings.append(embedding)
            except Exception as e:
                logger.error(f"Embedding error for text {i}: {e}")
                embeddings.append(np.zeros(self.llm_agent.dimension))
        
        return np.array(embeddings)
    
    def _embed_single(self, text: str, prefix: str = "") -> np.ndarray:
        """Embed one text with retries."""
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
        """Embed one text."""
        if self.llm_agent is None:
            return np.random.rand(3072)
        
        try:
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
        """Retrieve the top-k snippets by combined code and behavior similarity."""
        self._init_embedding_model()
        
        code_emb = self._embed_single(query_code, prefix="Code: ")
        behavior_emb = self._embed_single(query_behavior, prefix="Behavior: ")
        
        code_similarities = self._cosine_similarity(code_emb, self.code_embeddings)
        behavior_similarities = self._cosine_similarity(behavior_emb, self.behavior_embeddings)
        
        combined_scores = (
            code_weight * code_similarities + 
            behavior_weight * behavior_similarities
        )
        
        if self.clusters is not None and len(self.cluster_centroids) > 0:
            top_indices = self._cluster_anchored_topk(behavior_emb, combined_scores, top_k)
        else:
            top_indices = np.argsort(combined_scores)[::-1][:top_k]
        
        matches = []
        for snippet_idx in top_indices:
            snippet_idx = int(snippet_idx)
            
            pkg_id, snippet_idx_in_pkg = self.snippet_index[snippet_idx]
            
            package = self.packages_dict[pkg_id]
            
            snippet = package['malicious_snippets'][snippet_idx_in_pkg]
            
            matched_snippet = {
                'snippet_id': snippet.get('snippet_id', ''),
                'code_snippet': snippet.get('code_snippet', ''),
                'code_behavior': snippet.get('code_behavior', ''),
                'malice_analysis': snippet.get('malice_analysis', {}),
                'execution_context': snippet.get('execution_context', {}),
                
                'package_name': package['package_info'].get('package_name', 'unknown'),
                'package_manager': package['package_info'].get('package_manager', 'unknown'),
                'package_versions': package['package_info'].get('package_versions', ''),
                'why_malicious': package['package_info'].get('why_malicious', ''),
                
                'attack_chain': package['attack_chain'],
                'detection_knowledge': package['detection_knowledge']
            }
            
            match = KnowledgeMatch(
                match_id=f"{pkg_id}_{snippet.get('snippet_id', '')}",
                source_package=f"{package['package_info'].get('package_name', 'unknown')} ({package['package_info'].get('package_manager', 'unknown')})",
                source_file=package.get('source_file', 'unknown'),
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
        """Rank candidates from the closest behavior clusters, at most max_per_cluster per cluster."""
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
        if len(chosen) < top_k:
            for i in np.argsort(combined_scores)[::-1]:
                if int(i) not in chosen:
                    chosen.append(int(i))
                if len(chosen) >= top_k:
                    break
        return chosen
    
    @staticmethod
    def _cosine_similarity(query: np.ndarray, corpus: np.ndarray) -> np.ndarray:
        """Cosine similarity of a query against a matrix."""
        query = query / (np.linalg.norm(query) + 1e-10)
        corpus = corpus / (np.linalg.norm(corpus, axis=1, keepdims=True) + 1e-10)
        return np.dot(corpus, query)
    
    def _save_kb(self):
        """Write knowledge_base.json and the embedding matrices."""
        kb_file = self.kb_path / "knowledge_base.json"
        kb_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(kb_file, 'w', encoding='utf-8') as f:
            json.dump({
                'packages': self.packages,
                'metadata': {
                    'total_packages': len(self.packages),
                    'total_snippets': len(self.snippet_index),
                    'snippet_index': {str(k): v for k, v in self.snippet_index.items()}
                }
            }, f, indent=2, ensure_ascii=False)
        
        if self.code_embeddings is not None:
            np.save(self.kb_path / "snippet_code_embeddings.npy", self.code_embeddings)
            np.save(self.kb_path / "snippet_behavior_embeddings.npy", self.behavior_embeddings)
        
        logger.info(f"Knowledge base saved to {kb_file}")
    
    def load_kb(self):
        """Load the knowledge base, embeddings and clusters."""
        kb_file = self.kb_path / "knowledge_base.json"
        
        if not kb_file.exists():
            raise FileNotFoundError(f"Knowledge base not found at {kb_file}")
        
        with open(kb_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.packages = data['packages']
        
        self.packages_dict = {
            pkg['kb_id']: pkg 
            for pkg in self.packages
        }
        
        self.snippet_index = {
            int(k): tuple(v) 
            for k, v in data['metadata']['snippet_index'].items()
        }
        
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
        """Load clusters.json and the behavior centroids if present."""
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
        """Cluster counts and parameters."""
        if not self.clusters:
            return {}
        return {"behavior_clusters": len(self.clusters["behavior"]), "code_clusters": len(self.clusters["code"]),
                "params": self.clusters["params"]}

    def cluster_info_for(self, snippet_idx: int) -> Optional[Dict[str, Any]]:
        """Behavior cluster of a snippet, or None."""
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
    """Judge a code slice with retrieved knowledge and the LLM."""
    
    def __init__(
        self, 
        knowledge_base: RAGKnowledgeBase,
        llm_agent=None,
        similarity_threshold: Optional[float] = None
    ):
        """Bind the knowledge base, the LLM agent and the similarity threshold."""
        self.kb = knowledge_base
        self.llm_agent = llm_agent
        self.similarity_threshold = similarity_threshold
        self.detection_prompt = self._load_detection_prompt()
    
    def _load_detection_prompt(self) -> str:
        """Load the detection prompt template."""
        prompt_path = Path(__file__).parent / "rag_detection_prompt.txt"
        
        if prompt_path.exists():
            return prompt_path.read_text(encoding='utf-8')
        else:
            logger.warning(
                f"Detection prompt file not found at {prompt_path}. "
                "Using fallback prompt."
            )
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
    
    def _generate_behavior_summary(self, code: str) -> str:
        """Summarise the behavior of a code slice with the LLM."""
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
        """Ask the LLM for a verdict given the retrieved knowledge."""
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
        
        if not similar_matches:
            if no_match_reason:
                knowledge_context = f"""
**Note:** {no_match_reason}

Please analyze the code based on your own knowledge of malicious code patterns, 
common attack techniques, and security best practices.
"""
            else:
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
            knowledge_context = self._build_analysis_context(similar_matches)
        
        prompt = self.detection_prompt.format(
            code=code,
            behavior_summary=behavior,
            num_matches=len(similar_matches),
            knowledge_context=knowledge_context
        )

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm_agent.perform_query(messages, extract_json=True)
            
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
        """Format the retrieved snippets for the prompt."""
        context_parts = []
        
        for i, match in enumerate(matches[:3], 1):
            snippet = match.matched_snippet
            malice = snippet.get('malice_analysis', {})
            
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
        """Behavior cluster explanation of a match for the prompt."""
        ci = match.cluster_info
        if not ci or ci.get("behavior_cluster", -1) < 0:
            return ""
        return (f"**Behavior Concept (cluster of {ci.get('size')} known-malicious snippets from "
                f"{ci.get('n_packages')} reports):** {ci.get('unified_explanation')}. "
                f"Typical trigger(s): {', '.join(ci.get('top_triggers', {}).keys()) or 'n/a'}.")
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse the JSON verdict of the LLM."""
        import re
        
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = response
        
        try:
            result = json.loads(json_str)
            
            if 'is_malicious' in result:
                is_malicious_str = str(result.get('is_malicious', 'no')).lower()
                result['is_suspicious'] = is_malicious_str in ['yes', 'true', '1']
            
            result.setdefault('confidence', 0.0)
            result.setdefault('reasoning', '')
            result.setdefault('evidence', [])
            result.setdefault('malicious_behavior', 'none')
            result.setdefault('matched_patterns', [])
            
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}\nResponse: {response[:200]}")
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
        """Aggregate slice verdicts."""
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
        """Retrieve knowledge for a slice and return the LLM verdict."""
        similar_matches = self.kb.retrieve_similar(
            query_code=code_snippet,
            query_behavior=code_behavior,
            top_k=5
        )
        
        filtered_matches = similar_matches
        original_count = len(similar_matches)
        
        if self.similarity_threshold is not None and similar_matches:
            filtered_matches = [
                m for m in similar_matches 
                if m.similarity_score >= self.similarity_threshold
            ]
            
            if len(filtered_matches) < original_count:
                logger.info(
                    f"Filtered matches: {original_count} -> {len(filtered_matches)} "
                    f"(threshold: {self.similarity_threshold})"
                )
        
        if not filtered_matches:
            if original_count > 0 and self.similarity_threshold is not None:
                logger.info(
                    f"All {original_count} matches below threshold {self.similarity_threshold}, "
                    "relying on LLM's own knowledge"
                )
                llm_analysis = self._llm_enhanced_analysis(
                    code=code_snippet,
                    behavior=code_behavior,
                    similar_matches=[],
                    no_match_reason=f"No matches above similarity threshold {self.similarity_threshold}"
                )
            else:
                return DetectionResult(
                    is_malicious=False,
                    malice_score=0.0,
                    confidence=1.0,
                    explanation="No similar malicious patterns found in knowledge base, classified as benign code",
                    matched_knowledge=[]
                )
        else:
            llm_analysis = self._llm_enhanced_analysis(
                code=code_snippet,
                behavior=code_behavior,
                similar_matches=filtered_matches
            )
        
        is_malicious_str = str(llm_analysis.get('is_malicious', 'no')).lower()
        is_malicious = is_malicious_str in ['yes', 'true', '1']
        
        confidence = float(llm_analysis.get('confidence', 0.0))
        
        if filtered_matches:
            weights = [1.0, 0.8, 0.6, 0.4, 0.2][:len(filtered_matches)]
            weighted_sim = sum(m.similarity_score * w for m, w in zip(filtered_matches, weights))
            malice_score = weighted_sim / sum(weights)
        else:
            malice_score = 0.0
        
        reasoning = llm_analysis.get('reasoning', '')
        malicious_behavior = llm_analysis.get('malicious_behavior', 'none')
        
        if is_malicious:
            explanation = f"[LLM Judgment: Malicious] {reasoning}"
            if malicious_behavior != 'none':
                explanation += f" | Malicious Behavior: {malicious_behavior}"
        else:
            explanation = f"[LLM Judgment: Benign] {reasoning}"
        
        if self.similarity_threshold is not None and original_count > len(filtered_matches):
            explanation += f" | Similarity filter: {original_count} -> {len(filtered_matches)} matches (threshold: {self.similarity_threshold})"
        
        return DetectionResult(
            is_malicious=is_malicious,
            malice_score=malice_score,
            confidence=confidence,
            explanation=explanation,
            matched_knowledge=filtered_matches
        )


@dataclass
class DetectionResult:
    """Verdict of one code slice."""
    is_malicious: bool
    malice_score: float
    confidence: float
    matched_knowledge: List[KnowledgeMatch]
    explanation: str


def main():
    """Example usage."""
    kb = RAGKnowledgeBase(kb_path="/home2/wenbo/Documents/IntelliGraph/KnowledgeBase")
    
    
    try:
        kb.load_kb()
    except FileNotFoundError:
        logger.info("Building new knowledge base...")
        kb.build_from_verify_jsons("/home2/wenbo/Documents/IntelliGraph/Dataset/IntelliJson")
    
    


if __name__ == "__main__":
    main()

