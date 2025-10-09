#!/usr/bin/env python3
"""
RQ1 深度分析脚本：恶意代码片段的深层次分析
包括：行为分析、触发器分析、关键词提取、主题聚类等
"""

import json
import logging
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any, Set
import re
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DeepInsightsAnalyzer:
    """深度洞察分析器"""
    
    def __init__(self, dataset_dir: Path, output_dir: Path):
        self.dataset_dir = dataset_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 为 PyPI 和 NPM 分别创建数据收集容器
        self.data = {
            'pypi': self._create_data_containers(),
            'npm': self._create_data_containers()
        }
    
    def _create_data_containers(self) -> Dict[str, Any]:
        """创建数据收集容器"""
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
        """标准化trigger字段，提取核心触发点"""
        if not trigger or not trigger.strip():
            return "unspecified"
        
        trigger_lower = trigger.lower().strip()
        
        # 定义标准化规则（按顺序匹配）
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
        
        # 如果没有匹配到，返回前50个字符作为描述性标签
        return trigger[:50] + '...' if len(trigger) > 50 else trigger
    
    def extract_file_type(self, file_location: str) -> str:
        """从文件位置提取文件类型"""
        if not file_location:
            return "unknown"
        
        # 提取文件扩展名
        extensions = re.findall(r'\.(py|js|json|sh|exe|dll|so|jar|war|yaml|yml|conf|cfg|ini|bat|ps1|rb|go|java|c|cpp|h|hpp|php|asp|aspx|cs|vbs|wsf)(?:\b|$)', 
                               file_location.lower())
        if extensions:
            return extensions[0]
        
        # 识别特殊位置
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
        """从文本中提取关键词（基于频率和重要性）"""
        if not text:
            return []
        
        # 转小写并分词
        text_lower = text.lower()
        
        # 移除常见的停用词
        stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
            'as', 'this', 'that', 'these', 'those', 'it', 'its', 'can', 'may',
            'will', 'would', 'should', 'could', 'which', 'their', 'them', 'they',
            'such', 'not', 'also', 'any', 'all', 'if', 'when', 'where', 'how'
        }
        
        # 提取有意义的词组（2-3个词）
        bigrams = re.findall(r'\b[a-z]+(?:[-_][a-z]+)*\s+[a-z]+(?:[-_][a-z]+)*(?:\s+[a-z]+(?:[-_][a-z]+)*)?\b', text_lower)
        
        # 提取单个有意义的词（技术术语）
        technical_words = re.findall(r'\b(?:[a-z]+[-_])?[a-z]{4,}(?:[-_][a-z]+)?\b', text_lower)
        
        # 合并并统计
        all_terms = bigrams + technical_words
        filtered_terms = [t for t in all_terms if not any(sw in t.split() for sw in stopwords)]
        
        counter = Counter(filtered_terms)
        return counter.most_common(top_n)
    
    def extract_behavior_patterns(self, behavior_text: str) -> Set[str]:
        """从行为描述中提取行为模式"""
        if not behavior_text:
            return set()
        
        patterns = set()
        text_lower = behavior_text.lower()
        
        # 定义行为模式关键词
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
        """分析单个代码片段"""
        # 标准化 package_manager
        pm = package_manager.lower()
        if pm not in ['pypi', 'npm']:
            return
        
        data = self.data[pm]
        
        # 提取 execution_context
        exec_context = snippet.get('execution_context', {})
        trigger = exec_context.get('trigger', '')
        file_location = exec_context.get('file_location', '')
        permissions = exec_context.get('required_permissions', [])
        
        # 提取基本字段
        code_language = snippet.get('code_language', '')
        code_behavior = snippet.get('code_behavior', '')
        
        # 提取 malice_analysis
        malice = snippet.get('malice_analysis', {})
        why_suspicious = malice.get('why_suspicious', '')
        violated_expectations = malice.get('violated_expectations', '')
        similar_legitimate = malice.get('similar_legitimate_use', '')
        key_indicators = malice.get('key_indicators', [])
        
        # 收集数据
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
        """分析所有verify.json文件"""
        logger.info("🔍 开始收集和分析所有verify.json文件...")
        
        verify_files = list(self.dataset_dir.rglob('verify.json'))
        logger.info(f"找到 {len(verify_files)} 个verify.json文件")
        
        stats = {
            'pypi': {'total_reports': 0, 'reports_with_snippets': 0, 'total_snippets': 0},
            'npm': {'total_reports': 0, 'reports_with_snippets': 0, 'total_snippets': 0},
            'total': {'total_reports': 0, 'reports_with_snippets': 0, 'total_snippets': 0}
        }
        
        for verify_file in verify_files:
            try:
                with open(verify_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 提取 package_manager
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
                logger.warning(f"处理文件 {verify_file} 时出错: {e}")
                continue
        
        logger.info(f"✅ 分析完成！")
        logger.info(f"   总计: {stats['total']['total_reports']} 个报告，{stats['total']['reports_with_snippets']} 个有片段，{stats['total']['total_snippets']} 个片段")
        logger.info(f"   PyPI: {stats['pypi']['total_reports']} 个报告，{stats['pypi']['reports_with_snippets']} 个有片段，{stats['pypi']['total_snippets']} 个片段")
        logger.info(f"   NPM:  {stats['npm']['total_reports']} 个报告，{stats['npm']['reports_with_snippets']} 个有片段，{stats['npm']['total_snippets']} 个片段")
        
        return stats
    
    def generate_insights(self) -> Dict[str, Any]:
        """生成深度洞察分析结果"""
        logger.info("\n📊 开始生成深度洞察...")
        
        insights = {
            'pypi': self._generate_insights_for_pm('pypi'),
            'npm': self._generate_insights_for_pm('npm')
        }
        
        return insights
    
    def _generate_insights_for_pm(self, pm: str) -> Dict[str, Any]:
        """为指定的包管理器生成洞察"""
        logger.info(f"\n  分析 {pm.upper()} 生态系统...")
        
        data = self.data[pm]
        insights = {}
        
        # 1. Trigger 分析
        insights['trigger_analysis'] = {
            'total_triggers': len(data['triggers']),
            'unique_triggers': len(set(data['triggers'])),
            'normalized_distribution': dict(data['trigger_counter'].most_common(20)),
            'trigger_diversity': len(data['trigger_counter']) / max(len(data['triggers']), 1)
        }
        
        # 2. File Location 分析
        file_types = Counter([self.extract_file_type(loc) for loc in data['file_locations']])
        insights['file_location_analysis'] = {
            'total_locations': len(data['file_locations']),
            'file_type_distribution': dict(file_types.most_common(20)),
            'common_paths': self._extract_common_paths(data['file_locations'])
        }
        
        # 3. Code Language 分析
        insights['language_analysis'] = {
            'total_languages': len(data['language_counter']),
            'distribution': dict(data['language_counter'].most_common(30))
        }
        
        # 4. Code Behavior 深度分析
        behavior_patterns = Counter()
        for behavior in data['code_behaviors']:
            patterns = self.extract_behavior_patterns(behavior)
            for p in patterns:
                behavior_patterns[p] += 1
        
        behavior_keywords = Counter()
        for behavior in data['code_behaviors'][:100]:  # 采样前100个
            keywords = self.extract_keywords(behavior, top_n=10)
            for kw, count in keywords:
                behavior_keywords[kw] += count
        
        insights['behavior_analysis'] = {
            'total_behaviors': len(data['code_behaviors']),
            'behavior_patterns': dict(behavior_patterns.most_common(20)),
            'top_keywords': dict(behavior_keywords.most_common(30)),
            'avg_behavior_length': sum(len(b) for b in data['code_behaviors']) / max(len(data['code_behaviors']), 1)
        }
        
        # 5. Why Suspicious 分析
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
        
        # 6. Violated Expectations 分析
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
        
        # 7. Similar Legitimate Use 分析
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
        
        # 8. Key Indicators 分析
        indicator_counter = Counter(data['key_indicators_list'])
        indicator_patterns = self._extract_indicator_patterns(data['key_indicators_list'])
        
        insights['key_indicators_analysis'] = {
            'total_indicators': len(data['key_indicators_list']),
            'unique_indicators': len(set(data['key_indicators_list'])),
            'top_indicators': dict(indicator_counter.most_common(50)),
            'indicator_patterns': indicator_patterns
        }
        
        # 9. Required Permissions 分析
        insights['permissions_analysis'] = {
            'total_permissions': len(data['required_permissions_all']),
            'unique_permissions': len(data['permission_counter']),
            'distribution': dict(data['permission_counter'].most_common(30)),
            'permission_combinations': self._analyze_permission_combinations()
        }
        
        return insights
    
    def _extract_common_paths(self, file_locations: List[str]) -> Dict[str, int]:
        """提取常见路径模式"""
        path_patterns = Counter()
        
        for location in file_locations:
            # 提取常见路径模式
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
        """从key_indicators中提取模式"""
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
        """分析常见的权限组合（简化版）"""
        # 这里简化处理，返回单个权限的统计
        # 完整版本需要回溯原始snippet来分析组合
        return {"analysis": "See individual permissions distribution"}
    
    def save_results(self, insights: Dict[str, Any], stats: Dict[str, Any]):
        """保存分析结果"""
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
        
        logger.info(f"\n💾 深度分析结果已保存到: {output_file}")
        
        # 生成可读的报告
        self._generate_readable_report(insights, stats)
    
    def _generate_readable_report(self, insights: Dict[str, Any], stats: Dict[str, Any]):
        """生成可读的分析报告"""
        report_file = self.output_dir / 'rq1_deep_insights_report.txt'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("📊 RQ1 深度洞察分析报告（按生态系统分类）\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # 总体统计
            f.write("【总体统计】\n")
            f.write(f"总报告数: {stats['total']['total_reports']}\n")
            f.write(f"有效报告数: {stats['total']['reports_with_snippets']}\n")
            f.write(f"总代码片段数: {stats['total']['total_snippets']}\n\n")
            
            f.write("【PyPI 生态系统】\n")
            f.write(f"报告数: {stats['pypi']['total_reports']}\n")
            f.write(f"有效报告数: {stats['pypi']['reports_with_snippets']}\n")
            f.write(f"代码片段数: {stats['pypi']['total_snippets']}\n\n")
            
            f.write("【NPM 生态系统】\n")
            f.write(f"报告数: {stats['npm']['total_reports']}\n")
            f.write(f"有效报告数: {stats['npm']['reports_with_snippets']}\n")
            f.write(f"代码片段数: {stats['npm']['total_snippets']}\n\n")
            
            # 为每个生态系统生成详细报告
            for pm in ['pypi', 'npm']:
                self._write_pm_section(f, pm.upper(), insights[pm])
            
            f.write("="*80 + "\n")
            f.write("✅ 分析完成\n")
            f.write("="*80 + "\n")
        
        logger.info(f"📄 可读报告已保存到: {report_file}")
    
    def _write_pm_section(self, f, pm_name: str, pm_insights: Dict[str, Any]):
        """写入单个包管理器的分析章节"""
        f.write("\n")
        f.write("="*80 + "\n")
        f.write(f"【{pm_name} 生态系统详细分析】\n")
        f.write("="*80 + "\n\n")
        
        # 1. Trigger 分析
        f.write(f"【{pm_name} - 1. Trigger 触发器分析】\n")
        f.write(f"总触发器数: {pm_insights['trigger_analysis']['total_triggers']}\n")
        f.write(f"唯一触发器数: {pm_insights['trigger_analysis']['unique_triggers']}\n")
        f.write(f"触发器多样性: {pm_insights['trigger_analysis']['trigger_diversity']:.2%}\n")
        f.write("\n标准化后的Top 20触发器分布:\n")
        for trigger, count in list(pm_insights['trigger_analysis']['normalized_distribution'].items())[:20]:
            f.write(f"  {trigger}: {count}\n")
        f.write("\n")
        
        # 2. File Location 分析
        f.write(f"【{pm_name} - 2. File Location 文件位置分析】\n")
        f.write(f"总文件位置数: {pm_insights['file_location_analysis']['total_locations']}\n")
        f.write("\nTop 20 文件类型分布:\n")
        for ftype, count in list(pm_insights['file_location_analysis']['file_type_distribution'].items())[:20]:
            f.write(f"  {ftype}: {count}\n")
        f.write("\n常见路径模式:\n")
        for path, count in pm_insights['file_location_analysis']['common_paths'].items():
            f.write(f"  {path}: {count}\n")
        f.write("\n")
        
        # 3. Code Language 分析
        f.write(f"【{pm_name} - 3. Code Language 编程语言分析】\n")
        f.write(f"总语言类型数: {pm_insights['language_analysis']['total_languages']}\n")
        f.write("\nTop 30 语言分布:\n")
        for lang, count in list(pm_insights['language_analysis']['distribution'].items())[:30]:
            f.write(f"  {lang}: {count}\n")
        f.write("\n")
        
        # 4. Code Behavior 分析
        f.write(f"【{pm_name} - 4. Code Behavior 代码行为分析】\n")
        f.write(f"总行为描述数: {pm_insights['behavior_analysis']['total_behaviors']}\n")
        f.write(f"平均行为描述长度: {pm_insights['behavior_analysis']['avg_behavior_length']:.0f} 字符\n")
        f.write("\nTop 20 行为模式:\n")
        for pattern, count in list(pm_insights['behavior_analysis']['behavior_patterns'].items())[:20]:
            f.write(f"  {pattern}: {count}\n")
        f.write("\nTop 30 行为关键词:\n")
        for kw, count in list(pm_insights['behavior_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        # 5. Why Suspicious 分析
        f.write(f"【{pm_name} - 5. Why Suspicious 可疑原因分析】\n")
        f.write(f"总条目数: {pm_insights['why_suspicious_analysis']['total_entries']}\n")
        f.write(f"平均长度: {pm_insights['why_suspicious_analysis']['avg_length']:.0f} 字符\n")
        f.write("\nTop 30 关键词:\n")
        for kw, count in list(pm_insights['why_suspicious_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        # 6. Violated Expectations 分析
        f.write(f"【{pm_name} - 6. Violated Expectations 违反预期分析】\n")
        f.write(f"总条目数: {pm_insights['violated_expectations_analysis']['total_entries']}\n")
        f.write(f"平均长度: {pm_insights['violated_expectations_analysis']['avg_length']:.0f} 字符\n")
        f.write("\nTop 30 关键词:\n")
        for kw, count in list(pm_insights['violated_expectations_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        # 7. Similar Legitimate Use 分析
        f.write(f"【{pm_name} - 7. Similar Legitimate Use 合法用途对比分析】\n")
        f.write(f"总条目数: {pm_insights['similar_legitimate_analysis']['total_entries']}\n")
        f.write(f"平均长度: {pm_insights['similar_legitimate_analysis']['avg_length']:.0f} 字符\n")
        f.write("\nTop 30 关键词:\n")
        for kw, count in list(pm_insights['similar_legitimate_analysis']['top_keywords'].items())[:30]:
            f.write(f"  {kw}: {count}\n")
        f.write("\n")
        
        # 8. Key Indicators 分析
        f.write(f"【{pm_name} - 8. Key Indicators 关键指标分析】\n")
        f.write(f"总指标数: {pm_insights['key_indicators_analysis']['total_indicators']}\n")
        f.write(f"唯一指标数: {pm_insights['key_indicators_analysis']['unique_indicators']}\n")
        f.write("\nTop 50 关键指标:\n")
        for ind, count in list(pm_insights['key_indicators_analysis']['top_indicators'].items())[:50]:
            f.write(f"  {ind}: {count}\n")
        f.write("\n指标模式分布:\n")
        for pattern, count in pm_insights['key_indicators_analysis']['indicator_patterns'].items():
            f.write(f"  {pattern}: {count}\n")
        f.write("\n")
        
        # 9. Required Permissions 分析
        f.write(f"【{pm_name} - 9. Required Permissions 所需权限分析】\n")
        f.write(f"总权限数: {pm_insights['permissions_analysis']['total_permissions']}\n")
        f.write(f"唯一权限类型数: {pm_insights['permissions_analysis']['unique_permissions']}\n")
        f.write("\nTop 30 权限分布:\n")
        for perm, count in list(pm_insights['permissions_analysis']['distribution'].items())[:30]:
            f.write(f"  {perm}: {count}\n")
        f.write("\n")


def main():
    """主函数"""
    logger.info("="*80)
    logger.info("📊 RQ1: 恶意代码片段深度洞察分析（按生态系统分类）")
    logger.info("="*80)
    
    # 设置路径
    base_dir = Path(__file__).parent.parent.parent.parent  # 回到 IntelliGraph 根目录
    dataset_dir = base_dir / 'Dataset' / 'IntelliJson'
    output_dir = Path(__file__).parent / 'Results'
    
    logger.info(f"数据源目录: {dataset_dir}")
    logger.info(f"结果保存目录: {output_dir}")
    
    # 创建分析器
    analyzer = DeepInsightsAnalyzer(dataset_dir, output_dir)
    
    # 分析所有文件
    stats = analyzer.analyze_all_verify_files()
    
    # 生成深度洞察
    insights = analyzer.generate_insights()
    
    # 保存结果
    analyzer.save_results(insights, stats)
    
    logger.info("\n" + "="*80)
    logger.info("✅ 深度分析完成！")
    logger.info("="*80)


if __name__ == '__main__':
    main()
