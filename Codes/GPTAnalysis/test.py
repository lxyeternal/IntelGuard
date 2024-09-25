import json
import os
import re
import base64
import openai  # 0.28.1

config_path = os.path.join(os.path.dirname(__file__), "..", "..", "Configs", "config.json")
with open(config_path, 'r') as file:
    config = json.load(file)
openai.api_type = config['azure_api_type']
openai.api_base = config['azure_api_base']
openai.api_version = config['azure_api_version']
openai.api_key = config['azure_api_key']

# Function to encode the image
def encode_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')


# 函数：解析包含 image 标记的文本
def parse_text_with_images(text, base_dir, fixed_base_path):
    """
    解析文本，识别出所有 image: 路径 的标记，并返回一个按顺序排列的消息列表
    """
    messages = []
    # 正则匹配所有 image: 路径
    pattern = r'image:\s*([^\s]+)'
    parts = re.split(pattern, text)

    # re.split 会将文本按模式分割，并包含捕获组中的内容
    # 例如："text1 image: path1 text2 image: path2 text3" 会被分割为:
    # ["text1 ", "path1", " text2 ", "path2", " text3"]

    for index, part in enumerate(parts):
        if index % 2 == 0:
            # 偶数索引是文本
            if part.strip():
                messages.append({
                    "type": "text",
                    "text": part.strip()
                })
        else:
            # 奇数索引是图片路径
            image_rel_path = part.strip()

            # 处理路径分隔符，兼容反斜杠和斜杠
            image_rel_path = image_rel_path.replace('\\', '/')
            path_parts = image_rel_path.split('/')

            if len(path_parts) >= 2:
                # 提取最后两个部分
                last_two_parts = path_parts[-2:]
                # 拼接成新的相对路径
                new_rel_path = os.path.join(*last_two_parts)
                # 拼接固定的基础路径
                full_image_path = os.path.join(fixed_base_path, new_rel_path)
                # 规范化路径
                full_image_path = os.path.normpath(full_image_path)

                if os.path.exists(full_image_path):
                    base64_image = encode_image(full_image_path)
                    if base64_image:
                        messages.append({
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{base64_image}"
                            }
                        })
                else:
                    print(f"图片路径不存在: {full_image_path}")
                    # 如果图片不存在，可以选择将原始标记保留或替换为占位符
                    messages.append({
                        "type": "text",
                        "text": f"[图片不存在: {new_rel_path}]"
                    })
            else:
                print(f"图片路径格式不正确: {image_rel_path}")
                messages.append({
                    "type": "text",
                    "text": f"[无效的图片路径: {image_rel_path}]"
                })

    return messages


fig_path = '/Users/blue/Documents/GitHub/IntelliGraph/Dataset/Image/fortinet/20240708_170912_078565'

with open('/Users/blue/Documents/GitHub/IntelliGraph/Dataset/Content/medium_recommand/20240824_192433_921486.txt', 'r') as file:
    text = file.read()
messages = parse_text_with_images(text, "", "/Users/blue/Documents/GitHub/IntelliGraph/Dataset/Image/medium_recommand")

print(json.dumps(messages, ensure_ascii=False, indent=2))


completion =openai.ChatCompletion.create(
    model="gpt-4o",
    # engine="csl-malicious",
    engine="csl-malicious-4o-mini",
    messages=messages
)
chat_response = completion
answer = chat_response.choices[0].message.content
print(f'ChatGPT: {answer}')

