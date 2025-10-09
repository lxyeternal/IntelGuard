# RQ3: Knowledge Contribution Analysis

## Research Question
**RQ3: Knowledge Contribution** What is the contribution of expert knowledge to detection accuracy?

---

## Section 1: Data Analysis and Performance Comparison

The experimental results demonstrate significant performance improvements when integrating expert knowledge into malware detection. On the PyPI evaluation dataset, \tool{} achieves 99.00% accuracy with only 0.50% false positives and 1.50% false negatives, substantially outperforming GPT-4.1-mini (96.99% accuracy, 2.11% FPR, 3.90% FNR). The advantage of knowledge-enhanced detection becomes even more pronounced on obfuscated code: \tool{} maintains 96.50% accuracy with 4.32% FPR and 2.69% FNR, while GPT-4.1-mini's performance severely degrades to 52.82% accuracy with a catastrophic 84.86% false negative rate. GPT-4.1, despite being a more powerful model, exhibits excessive false positives (62.12% FPR) on obfuscated code, indicating over-sensitivity to code complexity. Similar trends are observed in the NPM ecosystem, where \tool{} achieves 98.72% accuracy with merely 0.20% false positives compared to GPT-4.1-mini's 96.70% accuracy and 2.30% FPR. Notably, \tool{} reduces false negatives from 44 (GPT-4.1-mini) to 24 cases in NPM, and from 880 to 28 cases in obfuscated PyPI packages, demonstrating superior malware detection capability across both ecosystems and code complexity levels.

---

## Section 2: Root Cause Analysis of Performance Differences

The fundamental limitation of direct LLM-based detection stems from the inherent ambiguity between malicious and legitimate code patterns when analyzed in isolation. Our case analysis reveals three critical failure modes in direct LLM detection. 

**First, contextual insufficiency**: LLMs lack historical attack pattern knowledge. For instance, package `anoularjs` performs a simple HTTPS GET request to `hits.dwyl.com` without transmitting sensitive data, which GPT-4.1-mini classifies as benign since the code appears functionally innocuous. However, \tool{} correctly identifies this as malicious (malice score 0.64, confidence 0.75) by matching it against known attack patterns from package `angulerjs` (similarity 0.67), recognizing that `hits.dwyl.com` is an established attacker-controlled domain used in typosquatting campaigns for command-and-control beaconing. 

**Second, obfuscation sensitivity imbalance**: GPT models exhibit contradictory behaviors toward code obfuscation. On obfuscated benign code like package `0bc8bcfb3f504a77a494db52ab6f2f8932fc766c`, both GPT-4.1 and GPT-4.1-mini incorrectly flag it as malicious due to suspicious variable names (e.g., `MOEwyUHQwEWWspVGbKLOkTFWMCAaoGUu`), interpreting obfuscation as inherently malicious intent. Conversely, when malware employs obfuscation strategically, GPT-4.1-mini's false negative rate spikes to 84.86%, as the model struggles to penetrate the obfuscated surface to identify underlying malicious logic. In contrast, \tool{} analyzes behavior summaries extracted via program slicing, which remain consistent regardless of variable naming, and compares these summaries against expert-verified malicious patterns—correctly identifying that the obfuscated benign code merely checks environment variables (matching VM detection patterns with low confidence 0.1), while truly malicious obfuscated code exhibits data exfiltration or C2 communication patterns. 

**Third, boundary detection inadequacy**: Direct LLM analysis lacks clear decision boundaries. For example, package `fpjc-test` contains a circular self-dependency in `package.json`, which GPT-4.1-mini flags as malicious "tactic to disrupt the package ecosystem." However, circular dependencies, while unusual, are not inherently malicious and can occur in legitimate testing or development scenarios. \tool{} correctly classifies this as benign by recognizing that the behavior summary (pure mathematical utility functions with no system/network operations) does not match any malicious attack chain, despite the suspicious dependency configuration.

---

## Section 3: Mechanisms and Advantages of Knowledge-Enhanced Detection

\tool{}'s superior performance is attributable to three key mechanisms enabled by expert knowledge integration. 

**First, behavior-based abstraction resilience**: By performing program slicing and extracting behavior summaries, \tool{} transforms detection from code-level analysis to semantic-level reasoning. This abstraction layer remains invariant to code obfuscation techniques (variable renaming, encoding, packing) that confound direct code analysis. For instance, while GPT models see different obfuscated variable names as distinct threats, \tool{} identifies functionally equivalent behaviors—both `os.environ.get('VIRTUAL_ENV')` and `os.environ.get('LC_DARK_BG')` involve environment variable access, but only the former matches known anti-sandbox evasion patterns in the knowledge base (snippet_2 from package `ccsinstaller`), enabling accurate discrimination. 

**Second, attack pattern contextualization**: The expert knowledge base encodes verified attack chains, behavioral signatures, and domain-specific indicators accumulated from real-world malware campaigns. This contextual knowledge enables \tool{} to recognize subtle indicators that appear benign in isolation but are diagnostic when contextualized. The `hits.dwyl.com` domain, for example, is indistinguishable from legitimate analytics endpoints without historical attack intelligence linking it to typosquatting campaigns. Similarly, \tool{} distinguishes between legitimate CI/CD environment checks and malicious sandbox evasion by comparing not just the API calls (`os.environ.get`), but the specific environment variables queried (`CI`, `VIRTUAL_ENV` vs. `LC_DARK_BG`) and their usage context (immediate `exit()` vs. configuration logging), leveraging matched knowledge from packages like `minimums` and `ccsinstaller` that document anti-analysis techniques. 

**Third, confidence-calibrated decision boundaries**: \tool{} employs a confidence scoring mechanism (combining code similarity and behavior similarity) that captures detection uncertainty. When behavior summaries partially match known patterns but lack conclusive indicators (e.g., environment variable access for terminal color settings vs. sandbox detection), \tool{} assigns low confidence scores (0.1) and defaults to benign classification, preventing false positives. Conversely, when multiple indicators align with known attack patterns (e.g., import-time network requests to known C2 domains with custom headers), high confidence scores (0.75) enable decisive malicious verdicts. This calibrated approach, grounded in empirically validated malicious patterns rather than speculative heuristics, explains \tool{}'s ability to maintain high precision (99.49% on PyPI evaluation, 99.80% on NPM) while simultaneously achieving high recall (98.50% and 97.67% respectively), effectively navigating the precision-recall tradeoff that limits direct LLM detection.

---

## Experimental Data Summary

### PyPI Dataset Results

| Dataset | Tool | Total Samples | Accuracy | Precision | Recall | F1 Score | FP | FN | FP Rate | FN Rate |
|---------|------|---------------|----------|-----------|--------|----------|----|----|---------|---------|
| evaluation | GPT-4.1 | 2000 | 96.30% | 94.86% | 97.90% | 96.36% | 53 | 21 | 5.30% | 2.10% |
| evaluation | GPT-4.1-mini | 1994 | 96.99% | 97.86% | 96.10% | 96.97% | 21 | 39 | 2.11% | 3.90% |
| evaluation | MalKG (\tool{}) | 2000 | **99.00%** | **99.49%** | **98.50%** | **98.99%** | **5** | **15** | **0.50%** | **1.50%** |
| obfuscation | GPT-4.1 | 2060 | 68.64% | 61.89% | 98.75% | 76.09% | 633 | 13 | 62.12% | 1.25% |
| obfuscation | GPT-4.1-mini | 2056 | 52.82% | 63.56% | 15.14% | 24.45% | 90 | 880 | 8.83% | 84.86% |
| obfuscation | MalKG (\tool{}) | 2060 | **96.50%** | **95.84%** | **97.31%** | **96.57%** | **44** | **28** | **4.32%** | **2.69%** |

### NPM Dataset Results

| Tool | Total | Benign | Malware | Accuracy | Precision | Recall | F1 Score | TP | TN | FP | FN | FP Rate | FN Rate |
|------|-------|--------|---------|----------|-----------|--------|----------|----|----|----|----|---------|---------|
| GPT-4.1-mini | 2033 | 999 | 1034 | 96.70% | 97.73% | 95.74% | 96.73% | 990 | 976 | 23 | 44 | 2.30% | 4.26% |
| MalKG (\tool{}) | 2027 | 999 | 1028 | **98.72%** | **99.80%** | **97.67%** | **98.72%** | **1004** | **997** | **2** | **24** | **0.20%** | **2.33%** |

---

## Key Case Studies

### Case 1: Contextual Insufficiency (NPM - anoularjs)

**GPT-4.1-mini Classification**: Benign (False Negative)
- **Reason**: Simple HTTPS GET request with no sensitive data transmission appears functionally innocuous

**\tool{} Classification**: Malicious (True Positive)
- **Malice Score**: 0.64
- **Confidence**: 0.75
- **Matched Pattern**: Package `angulerjs` (similarity 0.67)
- **Detection Reason**: Recognized `hits.dwyl.com` as established attacker-controlled domain used in typosquatting campaigns for C2 beaconing

**Code Snippet**:
```javascript
const https = require('https'); 
const options = { 
  hostname: 'hits.dwyl.com', 
  path: '/serialfuzzer/serialfuzzer', 
  method: 'GET' 
};
const req = https.request(options, (res) => { 
  res.on('data', (chunk) => {}); 
});
```

### Case 2: Obfuscation Sensitivity Imbalance (PyPI - 0bc8bcfb3f504a77a494db52ab6f2f8932fc766c)

**GPT-4.1 & GPT-4.1-mini Classification**: Malicious (False Positive)
- **Reason**: Suspicious variable names (e.g., `MOEwyUHQwEWWspVGbKLOkTFWMCAaoGUu`) interpreted as obfuscation indicating malicious intent

**\tool{} Classification**: Benign (True Negative)
- **Malice Score**: 0.47
- **Confidence**: 0.1
- **Detection Reason**: Behavior summary shows only environment variable access for terminal color settings, not matching anti-sandbox patterns with sufficient confidence

**Code Snippet**:
```python
from __pkginfo__ import MOEwyUHQwEWWspVGbKLOkTFWMCAaoGUu, author, classifiers
setup(name='k3gau8hq8f1r019b', version='1.0.0', 
      MqZAVIRiegsnvwmFpvOJxVGnoTLVUqZa='text/x-rst')
```

### Case 3: Boundary Detection Inadequacy (NPM - fpjc-test)

**GPT-4.1-mini Classification**: Malicious (False Positive)
- **Reason**: Circular self-dependency in `package.json` flagged as "tactic to disrupt the package ecosystem"

**\tool{} Classification**: Benign (True Negative)
- **Malice Score**: 0.50
- **Confidence**: 0.0
- **Detection Reason**: Behavior summary shows pure mathematical utility functions with no system/network operations, not matching any malicious attack chain

**package.json Snippet**:
```json
{
  "dependencies": {
    "fpjc-test": "0.0.1"
  }
}
```

---

## Conclusion

The integration of expert knowledge transforms LLM-based malware detection from surface-level code analysis to deep semantic understanding grounded in verified attack patterns. This approach achieves:

1. **Robustness to obfuscation**: 43.68% accuracy improvement on obfuscated PyPI code (96.50% vs. 52.82%)
2. **Precision enhancement**: 99.80% precision on NPM (vs. 97.73% for GPT-4.1-mini)
3. **False negative reduction**: 95% reduction in obfuscated PyPI false negatives (28 vs. 880)
4. **Consistent cross-ecosystem performance**: Superior results across both PyPI and NPM ecosystems

The expert knowledge base provides three critical capabilities absent in direct LLM detection: behavior-level abstraction resilient to code transformations, historical attack pattern contextualization for recognizing subtle indicators, and confidence-calibrated decision boundaries that effectively navigate the precision-recall tradeoff.

