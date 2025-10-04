# IntelliGraph

**An Intelligent Malicious Package Detection System with Knowledge Graph and RAG-enhanced Analysis**

IntelliGraph is an advanced security intelligence framework that combines Large Language Models (LLMs), Retrieval-Augmented Generation (RAG), and knowledge graph techniques to automatically detect and analyze malicious packages in software ecosystems (PyPI, npm, etc.).

---

## 🎯 Project Overview

IntelliGraph addresses the growing threat of supply chain attacks through malicious packages by:

1. **Automated Intelligence Collection**: Crawling and aggregating security reports from 19+ trusted sources
2. **LLM-powered Analysis**: Extracting structured knowledge from unstructured security reports  
3. **RAG-based Detection**: Building a knowledge base of malicious code patterns for intelligent detection
4. **Code Behavior Understanding**: Analyzing code at the behavioral level rather than simple pattern matching

### Key Features

- 🔍 **Multi-stage LLM Analysis Pipeline**: Relevance filtering → Entity extraction → Verification
- 📚 **Knowledge Graph Construction**: Structured representation of malicious behaviors and attack chains
- 🚀 **RAG-enhanced Detection**: Retrieval-augmented generation for context-aware malware identification
- 🧩 **Intelligent Code Slicing**: LLM-based code segmentation to identify distinct malicious behaviors
- ⚡ **Multi-process Support**: Parallel processing for large-scale analysis
- 🔄 **Incremental Knowledge Base**: Efficient updates without reprocessing existing data

---

## 📁 Project Structure

```
IntelliGraph/
│
├── Codes/                          # Source code modules
│   ├── Collection/                 # Intelligence data collection
│   │   ├── webpage_collection.py   # Blog/article link collection from security sources
│   │   ├── webpage_content.py      # Content extraction from webpages
│   │   ├── osv_collect/            # OSV (Open Source Vulnerabilities) database collection
│   │   └── pagelinks/              # Collected URLs and sources
│   │
│   ├── GPTAnalysis/                # LLM-based analysis pipeline
│   │   ├── intellgpt.py            # Three-stage LLM analysis (related → extract → verify)
│   │   ├── intellgpt_multiprocess.py  # Multi-process version for parallel processing
│   │   ├── llmquery.py             # LLM API interface (supports multiple providers)
│   │   ├── run_multiprocess.py     # Entry point for multi-process analysis
│   │   └── Prompts/                # Carefully crafted prompts for each stage
│   │       ├── intelli_related.txt      # Stage 1: Relevance analysis
│   │       ├── intelli_extract_v2.txt   # Stage 2: Entity extraction
│   │       └── intelli_verify_v2.txt    # Stage 3: Verification & structuring
│   │
│   ├── KnowledgeBase/              # RAG knowledge base management
│   │   ├── build_knowledge_base.py # Build/update knowledge base from verify.json files
│   │   ├── rag_detector.py         # RAG-based malware detection engine
│   │   └── view_knowledge_base.py  # Visualization and inspection tools
│   │
│   ├── Detect/                     # Detection modules
│   │   ├── package_detector.py     # End-to-end package malware detector
│   │   ├── code_slice.py           # LLM-based intelligent code slicing
│   │   └── code_slicing_prompt.txt # Code slicing strategy prompt
│   │
│   ├── IntelliSource/              # Source intelligence enrichment
│   │   ├── google_search.py        # Google search for additional context
│   │   ├── snykref_search.py       # Cross-reference with Snyk database
│   │   └── data_completion.py      # Data enrichment and completion
│   │
│   ├── Keywords/                   # Text processing and clustering
│   │   ├── textclean.py            # Text preprocessing
│   │   ├── topiccluster.py         # Topic clustering for knowledge organization
│   │   └── deduplication.py        # Duplicate detection
│   │
│   └── main.py                     # Main pipeline orchestrator
│
├── Dataset/                        # Data storage
│   ├── Content/                    # Raw text content from security blogs (19 sources)
│   ├── Image/                      # Downloaded images from articles
│   ├── IntelliJson/                # LLM-analyzed structured intelligence
│   │   ├── {source}/               # Organized by source
│   │   │   └── {timestamp}/
│   │   │       ├── related.json    # Stage 1: Relevance analysis result
│   │   │       ├── extract.json    # Stage 2: Extracted entities
│   │   │       └── verify.json     # Stage 3: Verified structured knowledge
│   └── Packages/                   # Sample malicious packages for testing
│
├── KnowledgeBase/                  # Persistent RAG knowledge base
│   ├── knowledge_base.json         # Structured malicious package knowledge
│   ├── snippet_code_embeddings.npy # Vector embeddings for code snippets
│   └── snippet_behavior_embeddings.npy  # Vector embeddings for behaviors
│
├── Results/                        # Detection results and reports
│   └── malware_detection/          # Package detection reports
│
├── Configs/                        # Configuration files
│   ├── config.py                   # General configuration
│   ├── llm_config.json             # LLM API configurations
│   └── metatrust-01-*.json         # Service credentials
│
└── utils/                          # Utility tools
    └── chromedriver/               # Web scraping tools (cross-platform)
```

---

## 🔄 System Workflow

### Phase 1: Intelligence Collection

```
Security Sources (Blogs) → Collection → Content Extraction → Storage
                ↓
    19+ sources including:
    • Snyk, JFrog, Checkmarx
    • ReversingLabs, Socket.dev
    • BleepingComputer, SecurityWeek
    • Medium, GitHub, Reddit, etc.
```

**Key Components:**
- `webpage_collection.py`: Automated crawling of security blogs
- `webpage_content.py`: Content parsing and image downloading
- Stores raw content in `Dataset/Content/{source}/`

### Phase 2: LLM-based Analysis (Three Stages)

```
Raw Content → Stage 1: Relevance → Stage 2: Extract → Stage 3: Verify → verify.json
              (Is it relevant?)     (Extract entities)   (Structure & validate)
```

**Stage 1 - Relevance Analysis:**
- Input: Raw article text
- Model: Small/fast LLM (e.g., GPT-4o-mini)
- Output: `related.json` - relevance score + preliminary filtering
- Purpose: Quick filtering to save API costs

**Stage 2 - Entity Extraction:**
- Input: Relevant articles + images (vision-capable LLM)
- Model: Large/capable LLM (e.g., GPT-4o)
- Output: `extract.json` - extracted package info, code snippets, behaviors
- Purpose: Extract structured intelligence from unstructured reports

**Stage 3 - Verification:**
- Input: Extracted entities
- Model: Large LLM with strict validation
- Output: `verify.json` - verified, complete structured knowledge
- Purpose: Ensure data quality and completeness

**verify.json Structure:**
```json
{
  "package_info": {
    "package_name": "malicious-package",
    "version": "1.0.0",
    "platform": "PyPI",
    "discovery_date": "2024-10-01"
  },
  "malicious_snippets": [
    {
      "code_snippet": "import socket; ...",
      "code_behavior": "Exfiltrates environment variables to attacker server",
      "location": "__init__.py",
      "language": "Python"
    }
  ],
  "attack_chain": [
    {"step": 1, "action": "Collect system info", ...},
    {"step": 2, "action": "Exfiltrate data", ...}
  ],
  "detection_knowledge": {
    "file_paths_accessed": ["/etc/passwd", "~/.ssh/"],
    "network_behaviors": ["POST data to malicious-domain.com"],
    "suspicious_api_calls": ["socket.socket", "subprocess.Popen"]
  }
}
```

### Phase 3: Knowledge Base Construction

```
verify.json files → Embedding Generation → Knowledge Base
                         ↓
            (Code + Behavior vectors)
                         ↓
         RAG-ready knowledge base
```

**Process:**
1. Load all `verify.json` files from `Dataset/IntelliJson/`
2. Extract `code_snippet` and `code_behavior` from each snippet
3. Generate embeddings using OpenAI embedding model
4. Build searchable vector index
5. Save to `KnowledgeBase/`:
   - `knowledge_base.json` - structured data
   - `snippet_code_embeddings.npy` - code vectors
   - `snippet_behavior_embeddings.npy` - behavior vectors

**Incremental Updates:**
- Automatically detects existing knowledge base
- Only processes new `verify.json` files
- Saves after each package (no progress loss on interruption)

### Phase 4: Malware Detection

```
Target Package → Code Slicing → RAG Retrieval → LLM Analysis → Detection Report
                      ↓              ↓                ↓
              (Functional      (Similar        (Context-aware
               behaviors)       patterns)        reasoning)
```

**Detection Pipeline:**

1. **Intelligent Code Slicing** (`code_slice.py`)
   - LLM analyzes code structure
   - Slices into minimal, independent functional fragments
   - Each slice represents a distinct security behavior
   - Avoids redundancy (groups related behaviors)

2. **RAG Retrieval** (`rag_detector.py`)
   - Generate embedding for each code slice
   - Search knowledge base for similar malicious patterns
   - Retrieve top-k most similar known malicious snippets
   - Provide context: code + behavior + package info

3. **LLM-enhanced Analysis**
   - Compare target slice with retrieved malicious patterns
   - Reason about behavioral similarity
   - Calculate malice score (0.0-1.0)
   - Generate explanation

4. **Report Generation**
   - Aggregate all slice detection results
   - Mark package as malicious if any slice exceeds threshold
   - Generate comprehensive JSON report with:
     - Detection verdict
     - Suspicious slices with scores
     - Retrieved similar malicious examples
     - Reasoning and explanations

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8+
pip install -r requirements.txt

# Install dependencies (example)
pip install openai anthropic numpy selenium beautifulsoup4 requests tqdm
```

### Configuration

1. **Set up LLM API credentials:**

Edit `Configs/llm_config.json`:
```json
{
  "openai": {
    "api_key": "your-openai-api-key",
    "model": "gpt-4o",
    "embedding_model": "text-embedding-3-large"
  }
}
```

2. **Configure analysis sources:**

Edit `Configs/config.py` for HTTP headers and user agents.

### Usage Examples

#### 1. Collect Intelligence

```bash
# Collect blog links from security sources
cd Codes/Collection
python webpage_collection.py

# Extract content from collected links
python webpage_content.py
```

#### 2. Analyze with LLM (Multi-process)

```bash
cd Codes/GPTAnalysis

# Run multi-process analysis (e.g., 8 parallel workers)
python run_multiprocess.py --source snyk --workers 8

# This will:
# - Process all .txt files in Dataset/Content/snyk/
# - Run three-stage LLM analysis
# - Generate verify.json files in Dataset/IntelliJson/snyk/
```

#### 3. Build Knowledge Base

```bash
cd Codes/KnowledgeBase

# Build knowledge base from all verify.json files
python build_knowledge_base.py

# Supports:
# - MAX_SAMPLES parameter to limit samples (for testing)
# - NUM_WORKERS for parallel processing
# - Automatic incremental updates (run again to add new data)
```

#### 4. Detect Malicious Packages

```bash
cd Codes/Detect

# Detect a PyPI package
python package_detector.py /path/to/package -m pypi

# Detect an npm package
python package_detector.py /path/to/package -m npm -t 0.6

# Options:
#   -m, --manager: Package manager type (pypi/npm)
#   -t, --threshold: Malice threshold (default: 0.5)
#   -o, --output: Output JSON path
#   --kb-path: Custom knowledge base path
```

**Example Output:**
```
🔍 端到端恶意包检测器
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 包信息
  路径: /path/to/suspicious-package
  类型: pypi
  文件数: 5

🧩 代码切片 (3 slices)
  ✓ main.py: 2 slices
  ✓ utils.py: 1 slice

🔍 RAG 检测
  [1/3] main.py#slice_1: 🚨 恶意 (0.87)
  [2/3] main.py#slice_2: ✓ 良性 (0.12)
  [3/3] utils.py#slice_1: ⚠️  可疑 (0.55)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  检测结果: 恶意包 (2/3 slices suspicious)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### 5. View Knowledge Base

```bash
cd Codes/KnowledgeBase

# View knowledge base statistics and sample entries
python view_knowledge_base.py
```

---

## 🔧 Advanced Usage

### Multi-process Analysis for Large Datasets

```python
from Codes.GPTAnalysis.intellgpt_multiprocess import IntelliLLMMultiProcess

# Initialize with 16 parallel workers
processor = IntelliLLMMultiProcess(num_processes=16)

# Process a source directory
processor.start(source_dir="checkmarx")
```

### Custom Knowledge Base Building

```python
from Codes.KnowledgeBase.rag_detector import RAGKnowledgeBase

# Initialize knowledge base
kb = RAGKnowledgeBase(kb_path="./custom_kb")

# Build from verify.json files (incremental mode)
kb.build_from_verify_jsons(
    intelli_json_dir="Dataset/IntelliJson",
    incremental=True  # Only process new packages
)

# Load existing knowledge base
kb.load_kb()
print(f"Loaded {len(kb.packages)} packages with {len(kb.snippet_index)} snippets")
```

### Programmatic Package Detection

```python
from Codes.Detect.package_detector import PackageMalwareDetector

# Initialize detector
detector = PackageMalwareDetector(
    kb_path="KnowledgeBase",
    malice_threshold=0.5
)

# Detect a package
result = detector.detect_package(
    package_path="/path/to/package",
    package_manager="pypi",
    output_json="detection_report.json"
)

# Check result
if result.is_malicious_package:
    print(f"⚠️ Malicious! Found {len(result.malicious_slices)} suspicious slices")
    for slice_result in result.malicious_slices:
        print(f"  - {slice_result.file_path}: {slice_result.explanation}")
```

---

## 📊 Supported Intelligence Sources

IntelliGraph collects intelligence from 19+ trusted security sources:

| Source | Focus Area | Articles |
|--------|-----------|----------|
| Snyk | Open source security | 381 |
| JFrog | Software supply chain | 612 |
| Checkmarx | Application security | 505 |
| Sonatype | Component analysis | 1331 |
| ReversingLabs | Malware analysis | 308 |
| Socket.dev | npm security | 275 |
| Phylum | Package analysis | 207 |
| Checkpoint | Threat intelligence | 631 |
| BleepingComputer | Security news | 93 |
| TheHackerNews | Security news | 1525 |
| Medium | Community articles | 386 |
| Others | Various sources | 1000+ |

Total: **7000+ analyzed security reports**

---

## 🛠️ Key Technologies

- **LLM Integration**: OpenAI GPT-4o, GPT-4o-mini, Anthropic Claude
- **Embeddings**: OpenAI text-embedding-3-large (3072 dimensions)
- **Vector Operations**: NumPy for efficient similarity search
- **Web Scraping**: Selenium, BeautifulSoup4, Requests
- **Parallel Processing**: Python multiprocessing, ProcessPoolExecutor
- **Data Formats**: JSON for structured data, NPY for embeddings

---

## 📈 Performance Optimization

### Knowledge Base Building
- **Incremental Updates**: Only process new verify.json files
- **Per-package Saving**: Save after each package (no progress loss)
- **Multi-process Support**: Up to 20 parallel workers
- **Progress Tracking**: Real-time logging with completion status

### Detection Performance
- **Efficient RAG**: Batch embedding generation
- **Smart Caching**: Reuse embeddings for repeated queries
- **Configurable Thresholds**: Balance false positives vs. detection rate

---

## 🔬 Research & Development

This project explores:

1. **Knowledge Graph for Security**: Representing malicious code patterns as structured knowledge
2. **RAG for Malware Detection**: Using retrieval-augmented generation for context-aware detection
3. **LLM Code Understanding**: Leveraging LLMs to understand code behavior semantically
4. **Automated Security Intelligence**: Building self-updating threat intelligence systems

---

## 📝 Example Workflow

Here's a complete end-to-end example:

```bash
# Step 1: Collect intelligence from Snyk blog
cd Codes/Collection
python webpage_collection.py  # Collects links
python webpage_content.py     # Extracts content

# Step 2: Analyze with LLM (8 parallel workers)
cd ../GPTAnalysis
python run_multiprocess.py --source snyk --workers 8

# Step 3: Build/update knowledge base
cd ../KnowledgeBase
python build_knowledge_base.py  # Incremental by default

# Step 4: Detect a suspicious package
cd ../Detect
python package_detector.py ~/Downloads/suspicious-pkg -m pypi

# Step 5: View results
cat ~/Documents/Github/IntelliGraph/Results/malware_detection/suspicious-pkg_report.json
```

---


**Built with ❤️ for securing the software supply chain**
