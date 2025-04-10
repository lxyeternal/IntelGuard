# !/usr/bin/env python
# -*- coding:utf-8 -*-
"""
# @File     : test
# @Project  : IntelliGraph
# Time      : 2/23/25 17:00
# Author    : blue
# version   : python 
# Description：
"""

# !/usr/bin/env python
# -*-coding:utf-8 -*-

import os
import json
import base64
from openai import AzureOpenAI


class ImageTest:
    def __init__(self):
        # 加载配置文件
        self.config_path = os.path.join(os.path.dirname(__file__), "..", "..", "Configs", "config.json")
        with open(self.config_path, 'r') as file:
            self.config = json.load(file)

        # 初始化 Azure OpenAI 客户端
        self.oclient = AzureOpenAI(
            api_key=self.config["azure_api_key"],
            api_version=self.config["azure_api_version"],
            azure_endpoint=self.config["azure_api_base"]
        )

    def encode_image(self, image_path):
        """将图片转换为base64编码"""
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')

    def analyze_image(self, image_path):
        """分析单张图片的内容"""
        try:
            # 检查图片是否存在
            if not os.path.exists(image_path):
                return f"Error: Image not found at path: {image_path}"

            # 将图片转换为base64
            base64_image = self.encode_image(image_path)

            # 构建消息
            messages = [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert specializing in analyzing images. Please describe what you see in the image in detail, focusing on any security-relevant content or suspicious elements."
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{base64_image}"
                            }
                        },
                        {
                            "type": "text",
                            "text": "Please analyze this image and describe what you see, focusing on any security-relevant details."
                        }
                    ]
                }
            ]

            # 调用API
            completion = self.oclient.chat.completions.create(
                model="gpt-4o",  # 使用原代码中的模型配置
                messages=messages,
                temperature=0,
                max_tokens=16000,
                top_p=0.3,
                frequency_penalty=0,
                presence_penalty=0,
                stop=None,
                stream=False
            )

            # 获取响应
            response = completion.choices[0].message.content
            return response

        except Exception as e:
            return f"Error analyzing image: {str(e)}"


def main():
    # 使用示例
    tester = ImageTest()

    # 指定测试图片路径
    test_image_path = "/Users/blue/Desktop/test.png"  # 替换为实际的图片路径

    # 分析图片
    result = tester.analyze_image(test_image_path)

    # 打印结果
    print("\nImage Analysis Result:")
    print(result)

    # 可选：将结果保存到文件
    with open("image_analysis_result.txt", "w", encoding="utf-8") as f:
        f.write(result)


if __name__ == "__main__":
    main()