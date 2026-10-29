#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
简单的OCR测试脚本
"""

import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from Codes.GPTAnalysis.ocr_interface import TesseractOCR


def test_ocr(image_path, lang="eng"):
    """测试OCR识别"""
    print(f"正在识别图片: {image_path}")
    print(f"使用语言: {lang}")
    print("-" * 80)
    
    try:
        ocr = TesseractOCR(lang=lang)
        result = ocr.recognize(image_path)
        
        print("OCR识别结果:")
        print("=" * 80)
        print(result)
        print("=" * 80)
        print(f"\n识别文本长度: {len(result)} 字符")
        
        return result
    except Exception as e:
        print(f"错误: {e}")
        return None


if __name__ == "__main__":
    # 测试指定的图片
    image_path = "/home2/wenbo/Documents/IntelliGraph/Dataset/Image/bleepingcomputer/20250102_111622_779955/VSCodeFigure35B15D.png"
    
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
    
    lang = "eng"
    if len(sys.argv) > 2:
        lang = sys.argv[2]
    
    test_ocr(image_path, lang)

