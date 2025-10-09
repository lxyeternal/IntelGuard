# 典型案例：从威胁情报中提取可操作知识

**来源**: Phylum威胁情报报告  
**包名**: certify, phylum-ci (PyPI)  
**版本**: certify-2024.2.2, phylum-ci-0.44.0  
**verify.json路径**: `/home2/wenbo/Documents/IntelliGraph/Dataset/IntelliJson/phylum/20240813_211342_779862/verify.json`

## 案例概述

这些恶意包利用现代Python构建后端（Hatch, PDM, Poetry）的build hook插件机制，在wheel构建过程中嵌入并执行恶意代码。该技术绕过了传统的setup.py静态分析，在构建时执行任意代码。

---

## 三种可操作知识的提取

### 1. 恶意代码片段 (Malicious Code Snippet)

**具体攻击实现**：

```python
from hatchling.builders.hooks.plugin.interface import BuildHookInterface

class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # Code in this function will run before building
        with open("/private/tmp/flag.txt", mode="w", encoding="utf-8") as f:
            f.write("Malware could have run here")
```

**触发时机**: wheel构建时（通过Hatch的pre-build hook）  
**文件位置**: `hatch_build.py`  
**所需权限**: 文件系统访问权限

---

### 2. 行为描述 (Behavioral Description)

**操作性说明**：

> "At wheel build-time (pre-build hook via Hatch), the code opens /private/tmp/flag.txt for writing, writes a marker string, and closes the file, resulting in unauthorized file creation outside the package directory."

**关键行为特征**：
- 在wheel构建期间执行任意Python代码（通过自定义build hooks）
- 向包目录外的位置写入文件（例如 /private/tmp/flag.txt）
- 使用非标准或误导性文件名作为build hook模块
- 存在未记录或非预期的build hook逻辑

---

### 3. 专家推理链 (Expert Reasoning)

**为什么可疑 (Why Suspicious)**：
> "The build hook executes arbitrary code that writes to a system directory outside the package scope during the build process, which is not required for legitimate package builds and can be leveraged for signaling, data exfiltration, or further compromise."

**违反的安全原则 (Violated Expectations)**：
- **原则1**: 标准build hooks应该只操作包目录内的文件或更新包元数据
- **原则2**: 写入无关系统位置（如 /private/tmp/flag.txt）明显偏离预期行为
- **原则3**: 构建过程不应在未经用户通知或同意的情况下修改系统文件

**关键判定指标**：
1. 在构建期间向 /private/tmp/flag.txt 任意写入文件
2. 通过Hatch build hook（initialize方法）执行代码
3. 无用户通知或对系统文件修改的同意
4. 存在带有自定义BuildHookInterface实现的hatch_build.py

**与合法用途的区别**：
合法的build hooks极少（如果有的话）会写入系统目录。在极少数情况下，构建可能会缓存构件，但这会有文档说明，而不是针对任意系统路径。

---

## 检测方法提取

基于上述三种知识，可以构建如下检测规则：

**静态分析**：
- 扫描源代码分发包中是否存在自定义build hook文件（如 hatch_build.py, pdm_build.py）
- 检查 pyproject.toml 中是否有可疑的build hook条目引用这些文件
- 标记任何包含对包目录外文件系统操作的build hook逻辑

**动态监控**：
- 监控构建过程中任何向包目录外的文件系统写入操作，特别是系统位置如 /private/tmp
- 在可能的情况下，禁止或沙箱化sdist安装以限制构建时代码执行

**行为签名**：
构建时代码执行 + 包目录外文件系统写入 + pyproject.toml中的自定义build hook配置

---

## 攻击新颖性

该案例展示了攻击者如何利用现代Python打包系统（绕过传统setup.py检测）进行攻击，具有以下特点：

1. **新型载体**: 利用Hatch/PDM/Poetry的build hook机制
2. **时机隐蔽**: 在构建时而非安装时执行
3. **检测困难**: 传统setup.py扫描器无法检测
4. **代码简洁**: 核心攻击代码仅5行，易于隐藏

