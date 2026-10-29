#!/usr/bin/env python3
"""LLM analysis of the four malice-analysis dimensions of the knowledge base."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import Counter, defaultdict
from datetime import datetime
import sys
import random

project_root = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from Codes.GPTAnalysis.llmquery import LLMAgent

PROJECT_ROOT = Path(__file__).resolve().parents[3]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


DATASET_DIR = f"{PROJECT_ROOT}/Dataset/IntelliJson"
OUTPUT_DIR = f"{PROJECT_ROOT}/Codes/Experiment/RQ1/Results"

SAMPLE_SIZE_PER_DIMENSION = 150
BATCH_SIZE = 30
MIN_TEXT_LENGTH = 20


class MaliceAnalysisData:
    """Collected malice-analysis texts."""
    
    def __init__(self):
        """Create empty collections."""
        self.why_suspicious = []
        self.violated_expectations = []
        self.similar_legitimate_use = []
        self.key_indicators = []
    
    def add_snippet(self, snippet: Dict[str, Any], context: Dict[str, Any]):
        """Add the malice analysis of one snippet."""
        if 'malice_analysis' not in snippet:
            return
        
        malice = snippet['malice_analysis']
        snippet_context = {
            'source': context.get('source', 'unknown'),
            'package': context.get('package', 'unknown'),
            'trigger': snippet.get('execution_context', {}).get('trigger', 'unknown'),
            'behavior': snippet.get('code_behavior', ''),
            'language': snippet.get('code_language', 'unknown')
        }
        
        if 'why_suspicious' in malice and malice['why_suspicious']:
            text = malice['why_suspicious'].strip()
            if len(text) >= MIN_TEXT_LENGTH:
                self.why_suspicious.append((text, snippet_context.copy()))
        
        if 'violated_expectations' in malice and malice['violated_expectations']:
            text = malice['violated_expectations'].strip()
            if len(text) >= MIN_TEXT_LENGTH:
                self.violated_expectations.append((text, snippet_context.copy()))
        
        if 'similar_legitimate_use' in malice and malice['similar_legitimate_use']:
            text = malice['similar_legitimate_use'].strip()
            if len(text) >= MIN_TEXT_LENGTH:
                self.similar_legitimate_use.append((text, snippet_context.copy()))
        
        if 'key_indicators' in malice and malice['key_indicators']:
            indicators = malice['key_indicators']
            if isinstance(indicators, list) and indicators:
                valid_indicators = [ind.strip() for ind in indicators if ind and ind.strip()]
                if valid_indicators:
                    self.key_indicators.append((valid_indicators, snippet_context.copy()))
    
    def summary(self) -> Dict[str, int]:
        """Counts per dimension."""
        return {
            'why_suspicious': len(self.why_suspicious),
            'violated_expectations': len(self.violated_expectations),
            'similar_legitimate_use': len(self.similar_legitimate_use),
            'key_indicators': len(self.key_indicators)
        }


def collect_malice_analysis_data() -> MaliceAnalysisData:
    """Collect malice-analysis data from all verify.json files."""
    data = MaliceAnalysisData()
    dataset_path = Path(DATASET_DIR)
    
    logger.info(f"Scanning dataset directory: {dataset_path}")
    
    file_count = 0
    for json_file in dataset_path.rglob("*.json"):
        try:
            if json_file.name not in ['extract.json', 'verify.json']:
                continue
            
            with open(json_file, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            file_count += 1
            
            context = {
                'source': json_file.parent.parent.name,
                'package': json_data.get('package_info', {}).get('package_name', 'unknown'),
                'file': str(json_file)
            }
            
            if 'report' in json_data:
                snippets = json_data['report'].get('code_snippets', [])
            elif 'malicious_snippets' in json_data:
                snippets = json_data['malicious_snippets']
            else:
                continue
            
            for snippet in snippets:
                data.add_snippet(snippet, context)
        
        except Exception as e:
            logger.debug(f"Skipping {json_file}: {e}")
            continue
    
    logger.info(f"✅ Processed {file_count} files")
    logger.info(f"✅ Collected data: {data.summary()}")
    
    return data


class MaliceAnalysisLLM:
    """LLM-based analysis of the collected texts."""
    
    def __init__(self):
        """Create the LLM agent."""
        self.llm = LLMAgent()
    
    def categorize_attacks(self, texts: List[Tuple[str, Dict]], sample_size: int = 100) -> Dict[str, Any]:
        """Classify why_suspicious texts into attack types."""
        logger.info(f"Classifying attack types (samples: {min(sample_size, len(texts))})")
        
        sampled = random.sample(texts, min(sample_size, len(texts)))
        
        category_counter = Counter()
        category_examples = defaultdict(list)
        
        for i, (text, context) in enumerate(sampled, 1):
            if i % 20 == 0:
                logger.info(f"  progress: {i}/{len(sampled)}")
            
            category = self._classify_single_attack(text)
            category_counter[category] += 1
            
            if len(category_examples[category]) < 3:
                category_examples[category].append({
                    'text': text[:300],
                    'trigger': context.get('trigger', 'unknown'),
                    'language': context.get('language', 'unknown'),
                    'source': context.get('source', 'unknown')
                })
        
        logger.info("Summarizing attack types...")
        summary = self._summarize_attacks([t[0] for t in sampled[:30]])
        
        return {
            'categories': dict(category_counter.most_common()),
            'examples': dict(category_examples),
            'summary': summary,
            'total_analyzed': len(sampled)
        }
    
    def _classify_single_attack(self, text: str) -> str:
        """Classify one text."""
        prompt = f"""Classify this malicious behavior into ONE category.

Text: {text[:500]}

Categories:
- data-exfiltration: Stealing credentials, files, or sensitive data
- cryptomining: Mining cryptocurrency without consent
- backdoor: Creating unauthorized remote access
- code-injection: Injecting malicious code
- privilege-escalation: Gaining elevated permissions
- persistence: Maintaining access across reboots
- reconnaissance: Collecting system information
- supply-chain: Compromising dependencies or build process
- vulnerability-exploitation: Exploiting known CVEs
- misconfiguration: Dangerous security misconfigurations
- obfuscation: Hiding malicious intent
- other: Other malicious behavior

Output in JSON format:
{{"category": "category-name"}}"""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.perform_query(messages, temperature=0.2, extract_json=True)
            import re
            json_match = re.search(r'\{.*?\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                category = result.get('category', 'other').strip().lower()
            else:
                category = response.strip().lower()
            
            valid_categories = [
                'data-exfiltration', 'cryptomining', 'backdoor', 'code-injection',
                'privilege-escalation', 'persistence', 'reconnaissance', 'supply-chain',
                'vulnerability-exploitation', 'misconfiguration', 'obfuscation', 'other'
            ]
            for vc in valid_categories:
                if vc in category:
                    return vc
            return 'other'
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return 'other'
    
    def _summarize_attacks(self, texts: List[str]) -> str:
        """Summarize attack patterns over a batch of texts."""
        prompt = f"""Analyze these {len(texts)} malicious behaviors and identify the top 5-7 attack patterns.

Behaviors:
"""
        for i, text in enumerate(texts[:20], 1):
            prompt += f"{i}. {text[:200]}\n"
        
        prompt += """

Provide a concise summary (3-5 sentences) of the most common attack patterns and their characteristics.
Output in JSON format: {"summary": "your summary here"}"""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.perform_query(messages, temperature=0.5, extract_json=True)
            import re
            json_match = re.search(r'\{.*?\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result.get('summary', response).strip()
            return response.strip()
        except Exception as e:
            logger.error(f"Summary failed: {e}")
            return "Failed to generate summary"
    
    def analyze_boundaries(self, violated_texts: List[Tuple[str, Dict]], 
                          legitimate_texts: List[Tuple[str, Dict]],
                          sample_size: int = 50) -> Dict[str, Any]:
        """Analyze the boundary between violated expectations and legitimate use."""
        logger.info(f"Analyzing boundaries...")
        
        violated_sample = random.sample(violated_texts, min(sample_size, len(violated_texts)))
        legitimate_sample = random.sample(legitimate_texts, min(sample_size, len(legitimate_texts)))
        
        pairs = []
        for v_text, v_ctx in violated_sample[:20]:
            for l_text, l_ctx in legitimate_sample:
                if v_ctx['source'] == l_ctx['source'] or v_ctx['trigger'] == l_ctx['trigger']:
                    pairs.append((v_text[:300], l_text[:300], v_ctx))
                    break
        
        logger.info(f"  {len(pairs)} paired samples")
        
        boundary_analysis = self._analyze_boundary_pairs(pairs[:10])
        
        diff_features = self._extract_diff_features(
            [t[0] for t in violated_sample[:30]],
            [t[0] for t in legitimate_sample[:30]]
        )
        
        return {
            'paired_examples': len(pairs),
            'boundary_analysis': boundary_analysis,
            'key_differences': diff_features,
            'violated_sample': [t[0][:200] for t in violated_sample[:5]],
            'legitimate_sample': [t[0][:200] for t in legitimate_sample[:5]]
        }
    
    def _analyze_boundary_pairs(self, pairs: List[Tuple[str, str, Dict]]) -> str:
        """Analyze paired violated/legitimate texts."""
        if not pairs:
            return "No paired samples found"
        
        prompt = """Analyze these pairs of VIOLATED (malicious) vs LEGITIMATE (normal) behaviors.
Identify the KEY DIFFERENCES that distinguish malicious from legitimate actions.

Pairs:
"""
        for i, (violated, legitimate, ctx) in enumerate(pairs[:5], 1):
            prompt += f"\nPair {i}:\n"
            prompt += f"  VIOLATED: {violated}\n"
            prompt += f"  LEGITIMATE: {legitimate}\n"
        
        prompt += """\n
Provide:
1. Top 3-5 key differentiating factors (what makes malicious behavior cross the line?)
2. Common patterns in how malicious code violates expectations

Be specific and actionable.
Output in JSON format: {"analysis": "your detailed analysis here"}"""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.perform_query(messages, temperature=0.4, extract_json=True)
            import re
            json_match = re.search(r'\{.*?\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result.get('analysis', response).strip()
            return response.strip()
        except Exception as e:
            logger.error(f"Boundary analysis failed: {e}")
            return "Failed to analyze boundaries"
    
    def _extract_diff_features(self, violated_texts: List[str], 
                               legitimate_texts: List[str]) -> List[str]:
        """Extract features that separate malicious from legitimate use."""
        prompt = f"""Compare these two groups and identify the KEY FEATURES that differentiate them.

MALICIOUS Behaviors ({len(violated_texts)} examples):
"""
        for i, text in enumerate(violated_texts[:10], 1):
            prompt += f"{i}. {text[:150]}\n"
        
        prompt += f"""\n
LEGITIMATE Behaviors ({len(legitimate_texts)} examples):
"""
        for i, text in enumerate(legitimate_texts[:10], 1):
            prompt += f"{i}. {text[:150]}\n"
        
        prompt += """

List 5-7 key features that distinguish malicious from legitimate.
Output in JSON format: {"features": ["feature1", "feature2", ...]}
"""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.perform_query(messages, temperature=0.3, extract_json=True)
            import re
            json_match = re.search(r'\{.*?\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result.get('features', [])[:7]
            features = []
            for line in response.split('\n'):
                line = line.strip()
                if line.startswith('-') or line.startswith('•'):
                    features.append(line.lstrip('-•').strip())
            return features[:7]
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return []
    
    def analyze_indicators(self, indicators_data: List[Tuple[List[str], Dict]], 
                          sample_size: int = 100) -> Dict[str, Any]:
        """Analyze the distribution of key indicators."""
        logger.info(f"Analyzing key indicators...")
        
        sampled = random.sample(indicators_data, min(sample_size, len(indicators_data)))
        
        all_indicators = []
        indicator_counter = Counter()
        for indicators, context in sampled:
            for ind in indicators:
                all_indicators.append((ind, context))
                category = self._categorize_indicator(ind)
                indicator_counter[category] += 1
        
        logger.info(f"  {len(all_indicators)} indicators collected")
        
        indicator_clusters = self._cluster_indicators([ind[0] for ind in all_indicators[:50]])
        
        frequent_patterns = self._find_frequent_patterns(all_indicators[:100])
        
        return {
            'total_indicators': len(all_indicators),
            'indicator_categories': dict(indicator_counter.most_common(15)),
            'indicator_clusters': indicator_clusters,
            'frequent_patterns': frequent_patterns,
            'sample_indicators': [ind[0][:150] for ind in all_indicators[:20]]
        }
    
    def _categorize_indicator(self, indicator: str) -> str:
        """Keyword-based indicator category."""
        indicator_lower = indicator.lower()
        
        if any(kw in indicator_lower for kw in ['network', 'http', 'connection', 'url', 'ip', 'domain', 'port']):
            return 'network'
        elif any(kw in indicator_lower for kw in ['file', 'path', 'directory', 'filesystem', '.py', '.js', '.exe']):
            return 'file'
        elif any(kw in indicator_lower for kw in ['process', 'execute', 'spawn', 'run', 'command']):
            return 'process'
        elif any(kw in indicator_lower for kw in ['obfuscate', 'encode', 'base64', 'encrypt', 'hide']):
            return 'obfuscation'
        elif any(kw in indicator_lower for kw in ['credential', 'password', 'token', 'api key', 'secret', 'ssh', 'aws']):
            return 'credential'
        elif any(kw in indicator_lower for kw in ['permission', 'privilege', 'root', 'admin', 'sudo']):
            return 'permission'
        elif any(kw in indicator_lower for kw in ['cve', 'vulnerability', 'exploit', 'patch']):
            return 'vulnerability'
        else:
            return 'other'
    
    def _cluster_indicators(self, indicators: List[str]) -> Dict[str, List[str]]:
        """Cluster indicators with the LLM."""
        prompt = f"""Analyze these {len(indicators)} detection indicators and group them into 5-7 meaningful clusters.

Indicators:
"""
        for i, ind in enumerate(indicators[:30], 1):
            prompt += f"{i}. {ind[:150]}\n"
        
        prompt += """

Provide clusters in JSON format:
{
  "cluster_name_1": ["indicator examples"],
  "cluster_name_2": ["indicator examples"],
  ...
}
"""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.perform_query(messages, temperature=0.4, extract_json=True)
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                clusters = json.loads(json_match.group())
                return clusters
            else:
                return {"parse_error": [response[:200]]}
        except Exception as e:
            logger.error(f"Indicator clustering failed: {e}")
            return {"error": [str(e)]}
    
    def _find_frequent_patterns(self, indicators_with_context: List[Tuple[str, Dict]]) -> List[Dict[str, Any]]:
        """Frequent indicator patterns."""
        pattern_groups = defaultdict(list)
        
        for ind, ctx in indicators_with_context:
            words = ind.split()[:3]
            pattern_key = ' '.join(words).lower()
            pattern_groups[pattern_key].append((ind, ctx))
        
        frequent = []
        for pattern, items in pattern_groups.items():
            if len(items) >= 3:
                frequent.append({
                    'pattern': pattern,
                    'count': len(items),
                    'examples': [item[0][:100] for item in items[:3]]
                })
        
        frequent.sort(key=lambda x: x['count'], reverse=True)
        return frequent[:10]


def main_analysis(data: MaliceAnalysisData) -> Dict[str, Any]:
    """Run the three analyses."""
    llm_analyzer = MaliceAnalysisLLM()
    results = {
        'metadata': {
            'analysis_date': datetime.now().isoformat(),
            'data_summary': data.summary()
        }
    }
    
    logger.info("\n" + "="*80)
    logger.info("[1] Why Suspicious - attack type classification")
    logger.info("="*80)
    results['why_suspicious_analysis'] = llm_analyzer.categorize_attacks(
        data.why_suspicious, 
        sample_size=SAMPLE_SIZE_PER_DIMENSION
    )
    
    logger.info("\n" + "="*80)
    logger.info("[2] Violated Expectations vs Similar Legitimate Use - boundary analysis")
    logger.info("="*80)
    results['boundary_analysis'] = llm_analyzer.analyze_boundaries(
        data.violated_expectations,
        data.similar_legitimate_use,
        sample_size=min(SAMPLE_SIZE_PER_DIMENSION, len(data.violated_expectations), len(data.similar_legitimate_use))
    )
    
    logger.info("\n" + "="*80)
    logger.info("[3] Key Indicators - detection feature analysis")
    logger.info("="*80)
    results['indicator_analysis'] = llm_analyzer.analyze_indicators(
        data.key_indicators,
        sample_size=SAMPLE_SIZE_PER_DIMENSION
    )
    
    return results


def generate_report(results: Dict[str, Any], output_path: Path):
    """Write the text report."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("Malice Analysis - 4 Dimensions\n")
        f.write("="*80 + "\n\n")
        
        meta = results['metadata']
        f.write(f"Date: {meta['analysis_date']}\n")
        f.write(f"Data:\n")
        for key, count in meta['data_summary'].items():
            f.write(f"  {key}: {count}\n")
        f.write("\n")
        
        f.write("="*80 + "\n")
        f.write("[1] Why Suspicious - attack types\n")
        f.write("="*80 + "\n\n")
        
        why_analysis = results['why_suspicious_analysis']
        f.write(f"Samples analyzed: {why_analysis['total_analyzed']}\n\n")
        
        f.write("Attack type distribution:\n")
        total = sum(why_analysis['categories'].values())
        for category, count in why_analysis['categories'].items():
            percentage = (count / total) * 100
            f.write(f"  {category}: {count} ({percentage:.1f}%)\n")
        f.write("\n")
        
        f.write("LLM summary:\n")
        f.write(why_analysis['summary'] + "\n\n")
        
        f.write("Examples per category:\n")
        for category, examples in sorted(why_analysis['examples'].items()):
            f.write(f"\n{category.upper()}:\n")
            f.write("-" * 60 + "\n")
            for i, ex in enumerate(examples, 1):
                f.write(f"Example {i}:\n")
                f.write(f"  {ex['text']}\n")
                f.write(f"  [Trigger: {ex['trigger']}, Language: {ex['language']}, Source: {ex['source']}]\n\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("[2] Violated Expectations vs Similar Legitimate Use - boundaries\n")
        f.write("="*80 + "\n\n")
        
        boundary = results['boundary_analysis']
        f.write(f"Paired samples: {boundary['paired_examples']}\n\n")
        
        f.write("Boundary analysis (malicious vs legitimate):\n")
        f.write("-" * 60 + "\n")
        f.write(boundary['boundary_analysis'] + "\n\n")
        
        f.write("Distinguishing features:\n")
        for i, feature in enumerate(boundary['key_differences'], 1):
            f.write(f"{i}. {feature}\n")
        f.write("\n")
        
        f.write("Violated Expectations examples:\n")
        for i, text in enumerate(boundary['violated_sample'], 1):
            f.write(f"{i}. {text}\n")
        f.write("\n")
        
        f.write("Similar Legitimate Use examples:\n")
        for i, text in enumerate(boundary['legitimate_sample'], 1):
            f.write(f"{i}. {text}\n")
        f.write("\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("[3] Key Indicators - detection features\n")
        f.write("="*80 + "\n\n")
        
        indicator = results['indicator_analysis']
        f.write(f"Indicators: {indicator['total_indicators']}\n\n")
        
        f.write("Indicator categories:\n")
        for category, count in indicator['indicator_categories'].items():
            f.write(f"  {category}: {count}\n")
        f.write("\n")
        
        f.write("Indicator clusters:\n")
        f.write("-" * 60 + "\n")
        for cluster_name, examples in indicator['indicator_clusters'].items():
            f.write(f"\n{cluster_name}:\n")
            for ex in examples[:3]:
                f.write(f"  - {ex}\n")
        f.write("\n")
        
        f.write("Frequent indicator patterns (top 10):\n")
        for i, pattern in enumerate(indicator['frequent_patterns'], 1):
            f.write(f"\n{i}. Pattern: {pattern['pattern']} ({pattern['count']} occurrences)\n")
            f.write("   examples:\n")
            for ex in pattern['examples']:
                f.write(f"     - {ex}\n")
        f.write("\n")
        
        f.write("Sample indicators:\n")
        for i, ind in enumerate(indicator['sample_indicators'][:15], 1):
            f.write(f"{i}. {ind}\n")
        f.write("\n")
    
    logger.info(f"📄 Report written: {output_path}")


def main():
    """Entry point."""
    
    logger.info("Starting the four-dimension malice analysis...")
    
    data = collect_malice_analysis_data()
    
    if data.summary()['why_suspicious'] == 0:
        logger.error("❌ Not enough data")
        return 1
    
    results = main_analysis(data)
    
    output_dir = Path(OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    json_path = output_dir / "malice_analysis_4d_llm.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"📄 JSON written: {json_path}")
    
    txt_path = output_dir / "malice_analysis_4d_report.txt"
    generate_report(results, txt_path)
    
    logger.info("✅ Done")
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interrupted")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

