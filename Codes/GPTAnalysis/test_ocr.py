#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Quick OCR check on one image."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from Codes.GPTAnalysis.ocr_interface import TesseractOCR


def test_ocr(image_path, lang="eng"):
    """Run OCR on an image and print the result."""
    print(f"Recognizing image: {image_path}")
    print(f"Language: {lang}")
    print("-" * 80)
    
    try:
        ocr = TesseractOCR(lang=lang)
        result = ocr.recognize(image_path)
        
        print("OCR result:")
        print("=" * 80)
        print(result)
        print("=" * 80)
        print(f"\nText length: {len(result)} characters")
        
        return result
    except Exception as e:
        print(f"Error: {e}")
        return None


if __name__ == "__main__":
    image_path = "/home2/wenbo/Documents/IntelliGraph/Dataset/Image/bleepingcomputer/20250102_111622_779955/VSCodeFigure35B15D.png"
    
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
    
    lang = "eng"
    if len(sys.argv) > 2:
        lang = sys.argv[2]
    
    test_ocr(image_path, lang)

