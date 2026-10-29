#!/usr/bin/env python3
"""Statistical analysis of the malicious snippets per ecosystem."""

import json
import logging
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any, Set
import re
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DeepInsightsAnalyzer:
    """Collect and summarize snippet fields per ecosystem."""
    
    def __init__(self, dataset_dir: Path, output_dir: Path):
        """Set the dataset and output directories."""
        self.dataset_dir = dataset_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.data = {
            'pypi': self._create_data_containers(),
            'npm': self._create_data_containers()
        }
    
    def _create_data_containers(self) -> Dict[str, Any]:
        """Empty per-field collections."""
        return {
            'triggers': [],
            'file_locations': [],
            'code_languages': [],
            'code_behaviors': [],
            'why_suspicious_texts': [],
            'violated_expectations_texts': [],
            'similar_legitimate_texts': [],
            'key_indicators_list': [],
            'required_permissions_all': [],
            'trigger_counter': Counter(),
            'language_counter': Counter(),
            'permission_counter': Counter()
        }
        
    def normalize_trigger(self, trigger: str) -> str:
        """Normalize a trigger description."""
        if not trigger or not trigger.strip():
            return "unspecified"
        
        trigger_lower = trigger.lower().strip()
        
        patterns = [
            (r'import[-\s]time', 'import-time'),
            (r'installation|install[-\s]time|setup\.py|pip install', 'installation'),
            (r'postinstall', 'postinstall'),
            (r'preinstall', 'preinstall'),
            (r'runtime|at runtime|during runtime', 'runtime'),
            (r'build[-\s]time|during build|compilation', 'build-time'),
            (r'startup|service startup|initialization', 'startup'),
            (r'on[-\s]demand|user[-\s]triggered|manual', 'on-demand'),
            (r'scheduled|periodic|cron', 'scheduled'),
            (r'boot|system boot', 'boot-time'),
            (r'login|authentication', 'login-time'),
        ]
        
        for pattern, standard_name in patterns:
            if re.search(pattern, trigger_lower):
                return standard_name
        
        return trigger[:50] + '...' if len(trigger) > 50 else trigger
    
    def extract_file_type(self, file_location: str) -> str:
        """File type of a file location."""
        if not file_location:
            return "unknown"
        
        extensions = re.findall(r'\.(py|js|json|sh|exe|dll|so|jar|war|yaml|yml|conf|cfg|ini|bat|ps1|rb|go|java|c|cpp|h|hpp|php|asp|aspx|cs|vbs|wsf)(?:\b|$)', 
                               file_location.lower())
        if extensions:
            return extensions[0]
        
        if 'setup.py' in file_location.lower():
            return 'setup.py'
        elif 'dockerfile' in file_location.lower():
            return 'Dockerfile'
        elif 'package.json' in file_location.lower():
            return 'package.json'
        elif 'requirements.txt' in file_location.lower():
            return 'requirements.txt'
        elif '.ssh' in file_location.lower():
            return 'ssh_config'
        elif '.aws' in file_location.lower():
            return 'aws_config'
        
        return "other"
    
    def extract_keywords(self, text: str, top_n: int = 20) -> List[tuple]:
        """Most frequent keywords of a text."""
        if not text:
            return []
        
        text_lower = text.lower()
        
        stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
            'as', 'this', 'that', 'these', 'those', 'it', 'its', 'can', 'may',
            'will', 'would', 'should', 'could', 'which', 'their', 'them', 'they',
            'such', 'not', 'also', 'any', 'all', 'if', 'when', 'where', 'how'
        }
        
        bigrams = re.findall(r'\b[a-z]+(?:[-_][a-z]+)*\s+[a-z]+(?:[-_][a-z]+)*(?:\s+[a-z]+(?:[-_][a-z]+)*)?\b', text_lower)
        
        technical_words = re.findall(r'\b(?:[a-z]+[-_])?[a-z]{4,}(?:[-_][a-z]+)?\b', text_lower)
        
        all_terms = bigrams + technical_words
        filtered_terms = [t for t in all_terms if not any(sw in t.split() for sw in stopwords)]
        
        counter = Counter(filtered_terms)
        return counter.most_common(top_n)
    
    def extract_behavior_patterns(self, behavior_text: str) -> Set[str]:
        """Behavior patterns of a behavior description."""
        if not behavior_text:
            return set()
        
        patterns = set()
        text_lower = behavior_text.lower()
        
        behavior_keywords = {
            'data_exfiltration': [r'exfiltrat', r'send.*data', r'upload.*file', r'transmit.*information'],
            'credential_theft': [r'steal.*credential', r'extract.*password', r'read.*\.ssh', r'read.*\.aws'],
            'remote_code_execution': [r'remote.*execut', r'arbitrary.*code', r'command.*injection', r'exec.*payload'],
            'privilege_escalation': [r'privilege.*escalat', r'root.*access', r'elevat.*permission', r'gain.*admin'],
            'persistence': [r'establish.*persistence', r'autostart', r'scheduled.*task', r'cron.*job'],
            'backdoor': [r'backdoor', r'reverse.*shell', r'remote.*access', r'c2.*communication'],
            'ransomware': [r'encrypt.*file', r'ransom', r'crypto.*locker'],
            'cryptomining': [r'crypto.*mining', r'mine.*cryptocurrency', r'mining.*pool'],
            'network_scanning': [r'port.*scan', r'network.*reconnaissance', r'service.*discovery'],
            'lateral_movement': [r'lateral.*movement', r'move.*laterally', r'spread.*network'],
            'defense_evasion': [r'evade.*detection', r'anti.*debug', r'obfuscat', r'hide.*process'],
            'data_destruction': [r'delete.*file', r'wipe.*data', r'destroy.*log'],
        }
        
        for pattern_name, keywords in behavior_keywords.items():
            for keyword_pattern in keywords:
                if re.search(keyword_pattern, text_lower):
                    patterns.add(pattern_name)
                    break
        
        return patterns
    
    def analyze_snippet(self, snippet: Dict[str, Any], package_manager: str):
        """Collect the fields of one snippet."""
        pm = package_manager.lower()
        if pm not in ['pypi', 'npm']:
            return
        
        data = self.data[pm]
        
        exec_context = snippet.get('execution_context', {})
        trigger = exec_context.get('trigger', '')
        file_location = exec_context.get('file_location', '')
        permissions = exec_context.get('required_permissions', [])
        
        code_language = snippet.get('code_language', '')
        code_behavior = snippet.get('code_behavior', '')
        
        malice = snippet.get('malice_analysis', {})
        why_suspicious = malice.get('why_suspicious', '')
        violated_expectations = malice.get('violated_expectations', '')
        similar_legitimate = malice.get('similar_legitimate_use', '')
        key_indicators = malice.get('key_indicators', [])
        
        if trigger:
            data['triggers'].append(trigger)
            normalized = self.normalize_trigger(trigger)
            data['trigger_counter'][normalized] += 1
        
        if file_location:
            data['file_locations'].append(file_location)
        
        if code_language:
            data['code_languages'].append(code_language)
            data['language_counter'][code_language] += 1
        
        if code_behavior:
            data['code_behaviors'].append(code_behavior)
        
        if why_suspicious:
            data['why_suspicious_texts'].append(why_suspicious)
        
        if violated_expectations:
            data['violated_expectations_texts'].append(violated_expectations)
        
        if similar_legitimate:
            data['similar_legitimate_texts'].append(similar_legitimate)
        
        if key_indicators:
            data['key_indicators_list'].extend(key_indicators)
        
        for perm in permissions:
            if perm:
                data['permission_counter'][perm] += 1
                data['required_permissions_all'].append(perm)
    
    def analyze_all_verify_files(self):
        """Collect all snippets and return the counts."""
        logger.info("Analyzing all verify.json files...")
        
        verify_files = list(self.dataset_dir.rglob('verify.json'))
        logger.info(f"Found {len(verify_files)} verify.json files")
        
        stats = {
            'pypi': {'total_reports': 0, 'reports_with_snippets': 0, 'total_snippets': 0},
            'npm': {'total_reports': 0, 'reports_with_snippets': 0, 'total_snippets': 0},
            'total': {'total_reports': 0, 'reports_with_snippets': 0, 'total_snippets': 0}
        }
        
        for verify_file in verify_files:
            try:
                with open(verify_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                package_info = data.get('package_info', {})
                package_manager = package_info.get('package_manager', '').lower()
                
                if package_manager not in ['pypi', 'npm']:
                    continue
                
                stats[package_manager]['total_reports'] += 1
                stats['total']['total_reports'] += 1
                
                snippets = data.get('malicious_snippets', [])
                
                if snippets:
                    stats[package_manager]['reports_with_snippets'] += 1
                    stats[package_manager]['total_snippets'] += len(snippets)
                    stats['total']['reports_with_snippets'] += 1
                    stats['total']['total_snippets'] += len(snippets)
                    
                    for snippet in snippets:
                        self.analyze_snippet(snippet, package_manager)
                        
            except Exception as e:
                logger.warning(f"Error processing {verify_file}: {e}")
                continue
        
        logger.info(f"Done")
        logger.info(f"   total: {stats['total']['total_reports']} reports, {stats['total']['reports_with_snippets']} with snippets, {stats['total']['total_snippets']} snippets")
        logger.info(f"   PyPI: {stats['pypi']['total_reports']} reports, {stats['pypi']['reports_with_snippets']} with snippets, {stats['pypi']['total_snippets']} snippets")
        logger.info(f"   NPM:  {stats['npm']['total_reports']} reports, {stats['npm']['reports_with_snippets']} with snippets, {stats['npm']['total_snippets']} snippets")
        
        return stats
    
    def generate_insights(self) -> Dict[str, Any]:
        """Insights for both ecosystems."""
        logger.info("\n📊 Generating insights...")
        
        insights = {
            'pypi': self._generate_insights_for_pm('pypi'),
            'npm': self._generate_insights_for_pm('npm')
        }
        
        return insights
    
    def _generate_insights_for_pm(self, pm: str) -> Dict[str, Any]:
        """Insights for one ecosystem."""
        logger.info(f"\n  {pm.upper()} ecosystem...")
        
        data = self.data[pm]
        insights = {}
        
        insights['trigger_analysis'] = {
            'total_triggers': len(data['triggers']),
            'unique_triggers': len(set(data['triggers'])),
            'normalized_distribution': dict(data['trigger_counter'].most_common(20)),
            'trigger_diversity': len(data['trigger_counter']) / max(len(data['triggers']), 1)
        }
        
        file_types = Counter([self.extract_file_type(loc) for loc in data['file_locations']])
        insights['file_location_analysis'] = {
            'total_locations': len(data['file_locations']),
            'file_type_distribution': dict(file_types.most_common(20)),
            'common_paths': self._extract_common_paths(data['file_locations'])
        }
        
        insights['language_analysis'] = {
            'total_languages': len(data['language_counter']),
            'distribution': dict(data['language_counter'].most_common(30))
        }
        
        behavior_patterns = Counter()
        for behavior in data['code_behaviors']:
            patterns = self.extract_behavior_patterns(behavior)
            for p in patterns:
                behavior_patterns[p] += 1
        
        behavior_keywords = Counter()
        for behavior in data['code_behaviors'][:100]:
            keywords = self.extract_keywords(behavior, top_n=10)
            for kw, count in keywords:
                behavior_keywords[kw] += count
        
        insights['behavior_analysis'] = {
            'total_behaviors': len(data['code_behaviors']),
            'behavior_patterns': dict(behavior_patterns.most_common(20)),
            'top_keywords': dict(behavior_keywords.most_common(30)),
            'avg_behavior_length': sum(len(b) for b in data['code_behaviors']) / max(len(data['code_behaviors']), 1)
        }
        
        suspicious_keywords = Counter()
        for text in data['why_suspicious_texts'][:100]:
            keywords = self.extract_keywords(text, top_n=10)
            for kw, count in keywords:
                suspicious_keywords[kw] += count
        
        insights['why_suspicious_analysis'] = {
            'total_entries': len(data['why_suspicious_texts']),
            'top_keywords': dict(suspicious_keywords.most_common(30)),
            'avg_length': sum(len(t) for t in data['why_suspicious_texts']) / max(len(data['why_suspicious_texts']), 1)
        }
        
        violation_keywords = Counter()
        for text in data['violated_expectations_texts'][:100]:
            keywords = self.extract_keywords(text, top_n=10)
            for kw, count in keywords:
                violation_keywords[kw] += count
        
        insights['violated_expectations_analysis'] = {
            'total_entries': len(data['violated_expectations_texts']),
            'top_keywords': dict(violation_keywords.most_common(30)),
            'avg_length': sum(len(t) for t in data['violated_expectations_texts']) / max(len(data['violated_expectations_texts']), 1)
        }
        
        legitimate_keywords = Counter()
        for text in data['similar_legitimate_texts'][:100]:
            keywords = self.extract_keywords(text, top_n=10)
            for kw, count in keywords:
                legitimate_keywords[kw] += count
        
        insights['similar_legitimate_analysis'] = {
            'total_entries': len(data['similar_legitimate_texts']),
            'top_keywords': dict(legitimate_keywords.most_common(30)),
            'avg_length': sum(len(t) for t in data['similar_legitimate_texts']) / max(len(data['similar_legitimate_texts']), 1)
        }
        
        indicator_counter = Counter(data['key_indicators_list'])
        indicator_patterns = self._extract_indicator_patterns(data['key_indicators_list'])
        
        insights['key_indicators_analysis'] = {
            'total_indicators': len(data['key_indicators_list']),
            'unique_indicators': len(set(data['key_indicators_list'])),
            'top_indicators': dict(indicator_counter.most_common(50)),
            'indicator_patterns': indicator_patterns
        }
        
        insights['permissions_analysis'] = {
            'total_permissions': len(data['required_permissions_all']),
            'unique_permissions': len(data['permission_counter']),
            'distribution': dict(data['permission_counter'].most_common(30)),
            'permission_combinations': self._analyze_permission_combinations()
        }
        
        return insights
    
    def _extract_common_paths(self, file_locations: List[str]) -> Dict[str, int]:
        """Common path patterns."""
        path_patterns = Counter()
        
        for location in file_locations:
            patterns = [
                r'setup\.py',
                r'package\.json',
                r'requirements\.txt',
                r'Dockerfile',
                r'\.ssh',
                r'\.aws',
                r'\.kube',
                r'\.npmrc',
                r'/tmp',
                r'/etc',
                r'/usr',
                r'/home',
                r'node_modules',
                r'site-packages',
            ]
            
            for pattern in patterns:
                if re.search(pattern, location, re.IGNORECASE):
                    path_patterns[pattern] += 1
        
        return dict(path_patterns.most_common(20))
    
    def _extract_indicator_patterns(self, key_indicators_list: List[str]) -> Dict[str, int]:
        """Indicator patterns."""
        patterns = Counter()
        
        pattern_keywords = [
            'base64', 'obfuscation', 'hardcoded', 'encrypted', 'encoded',
            'suspicious', 'unauthorized', 'unexpected', 'malicious',
            'exfiltration', 'backdoor', 'c2', 'command', 'execution',
            'network', 'file', 'registry', 'process', 'permission'
        ]
        
        for indicator in key_indicators_list:
            indicator_lower = indicator.lower()
            for keyword in pattern_keywords:
                if keyword in indicator_lower:
                    patterns[keyword] += 1
        
        return dict(patterns.most_common(20))
    
    def _analyze_permission_combinations(self) -> Dict[str, int]:
        """Permission combinations."""
        return {"analysis": "See individual permissions distribution"}
    
    def save_results(self, insights: Dict[str, Any], stats: Dict[str, Any]):
        """Write the JSON results and the text report."""
        output_file = self.output_dir / 'rq1_deep_insights.json'
        
        result = {
            'metadata': {
                'analysis_date': datetime.now().isoformat(),
                'dataset_directory': str(self.dataset_dir),
                'total': stats['total'],
                'pypi': stats['pypi'],
                'npm': stats['npm']
            },
            'insights': insights
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n💾 Results written to: {output_file}")
        
        self._generate_readable_report(insights, stats)
    
    def _generate_readable_report(self, insights: Dict[str, Any], stats: Dict[str, Any]):
        """Write the text report."""
        report_file = self.output_dir / 'rq1_deep_insights_report.txt'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("RQ1 insight report by ecosystem\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("[Overall]\n")
            f.write(f"Reports: {stats['total']['total_reports']}\n")
            f.write(f"Reports with snippets: {stats['total']['reports_with_snippets']}\n")
            f.write(f"Snippets: {stats['total']['total_snippets']}\n\n")
            
            f.write("[PyPI]\n")
            f.write(f"Reports: {stats['pypi']['total_reports']}\n")
            f.write(f"Reports with snippets: {stats['pypi']['reports_with_snippets']}\n")
            f.write(f"Snippets: {stats['pypi']['total_snippets']}\n\n")
            
            f.write("[NPM]\n")
            f.write(f"Reports: {stats['npm']['total_reports']}\n")
            f.write(f"Reports with snippets: {stats['npm']['reports_with_snippets']}\n")
            f.write(f"Snippets: {stats['npm']['total_snippets']}\n\n")
            
            for pm in ['pypi', 'npm']:
                self._write_pm_section(f, pm.upper(), insights[pm])
            
            f.write("="*80 + "\n")
            f.write("Done\n")
            f.write("="*80 + "\n")
        
        logger.info(f"📄 Report written to: {report_file}")
    
    def _write_pm_section(self, f, pm_name: str, pm_insights: Dict[str, Any]):
        """Write the report section of one ecosystem."""
        f.write("\n")
        f.write("="*80 + "\n")
        f.write(f"[{pm_name} ecosystem]\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"[{pm_name} - 1. Triggers]\n")
        f.write(f"Triggers: {pm_insights['trigger_analysis']['total_triggers']}\n")
        f.write(f"Unique triggers: {pm_insights['trigger_analysis']['unique_triggers']}\n")
        f.write(f"Trigger diversity: {pm_insights['trigger_analysis']['trigger_diversity']:.2%}\n")
        f.write("\nTop 20 normalized triggers:\n")
        for trigger, count in list(pm_insights['trigger_analysis']['normalized_distribution'].items())[:20]:
            f.write(f"  {trigger}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 2. File locations]\n")
        f.write(f"File locations: {pm_insights['file_location_analysis']['total_locations']}\n")
        f.write("\nTop 20 file types:\n")
        for ftype, count in list(pm_insights['file_location_analysis']['file_type_distribution'].items())[:20]:
            f.write(f"  {ftype}: {count}\n")
        f.write("\nCommon path patterns:\n")
        for path, count in pm_insights['file_location_analysis']['common_paths'].items():
            f.write(f"  {path}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 3. Languages]\n")
        f.write(f"Languages: {pm_insights['language_analysis']['total_languages']}\n")
        f.write("\nTop 30 languages:\n")
        for lang, count in list(pm_insights['language_analysis']['distribution'].items())[:30]:
            f.write(f"  {lang}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 4. Code behavior]\n")
        f.write(f"Behavior descriptions: {pm_insights['behavior_analysis']['total_behaviors']}\n")
        f.write(f"Average behavior length: {pm_insights['behavior_analysis']['avg_behavior_length']:.0f} characters\n")
        f.write("\nTop 20 behavior patterns:\n")
        for pattern, count in list(pm_insights['behavior_analysis']['behavior_patterns'].items())[:20]:
            f.write(f"  {pattern}: {count}\n")
        f.write("\nTop 30 behavior keywords:\n")
        for kw, count in list(pm_insights['behavior_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 5. Why suspicious]\n")
        f.write(f"Entries: {pm_insights['why_suspicious_analysis']['total_entries']}\n")
        f.write(f"Average length: {pm_insights['why_suspicious_analysis']['avg_length']:.0f} characters\n")
        f.write("\nTop 30 keywords:\n")
        for kw, count in list(pm_insights['why_suspicious_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 6. Violated expectations]\n")
        f.write(f"Entries: {pm_insights['violated_expectations_analysis']['total_entries']}\n")
        f.write(f"Average length: {pm_insights['violated_expectations_analysis']['avg_length']:.0f} characters\n")
        f.write("\nTop 30 keywords:\n")
        for kw, count in list(pm_insights['violated_expectations_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 7. Similar legitimate use]\n")
        f.write(f"Entries: {pm_insights['similar_legitimate_analysis']['total_entries']}\n")
        f.write(f"Average length: {pm_insights['similar_legitimate_analysis']['avg_length']:.0f} characters\n")
        f.write("\nTop 30 keywords:\n")
        for kw, count in list(pm_insights['similar_legitimate_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 8. Key indicators]\n")
        f.write(f"Indicators: {pm_insights['key_indicators_analysis']['total_indicators']}\n")
        f.write(f"Unique indicators: {pm_insights['key_indicators_analysis']['unique_indicators']}\n")
        f.write("\nTop 50 indicators:\n")
        for ind, count in list(pm_insights['key_indicators_analysis']['top_indicators'].items())[:50]:
            f.write(f"  {ind}: {count}\n")
        f.write("\nIndicator patterns:\n")
        for pattern, count in pm_insights['key_indicators_analysis']['indicator_patterns'].items():
            f.write(f"  {pattern}: {count}\n")
        f.write("\n")
        
        f.write(f"[{pm_name} - 9. Required permissions]\n")
        f.write(f"Permissions: {pm_insights['permissions_analysis']['total_permissions']}\n")
        f.write(f"Unique permissions: {pm_insights['permissions_analysis']['unique_permissions']}\n")
        f.write("\nTop 30 permissions:\n")
        for perm, count in list(pm_insights['permissions_analysis']['distribution'].items())[:30]:
            f.write(f"  {perm}: {count}\n")
        f.write("\n")


def main():
    """Entry point."""
    logger.info("="*80)
    logger.info("RQ1: malicious snippet analysis by ecosystem")
    logger.info("="*80)
    
    base_dir = Path(__file__).parent.parent.parent.parent
    dataset_dir = base_dir / 'Dataset' / 'IntelliJson'
    output_dir = Path(__file__).parent / 'Results'
    
    logger.info(f"Dataset directory: {dataset_dir}")
    logger.info(f"Output directory: {output_dir}")
    
    analyzer = DeepInsightsAnalyzer(dataset_dir, output_dir)
    
    stats = analyzer.analyze_all_verify_files()
    
    insights = analyzer.generate_insights()
    
    analyzer.save_results(insights, stats)
    
    logger.info("\n" + "="*80)
    logger.info("✅ Done")
    logger.info("="*80)


if __name__ == '__main__':
    main()
