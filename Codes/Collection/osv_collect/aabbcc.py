# 读取文件内容
with open('article_links2.txt', 'r') as file:
    lines = file.readlines()

# 处理每一行，修改源部分，去除 "www." 和 ".com"
modified_lines = []
for line in lines:
    parts = line.split()  # 按空格分割每一行
    source = parts[2]  # 获取源部分
    # 删除 "www." 和 ".com"
    source = source.replace('www.', '').replace('.com', '')
    parts[2] = source  # 更新源部分
    modified_lines.append("\t".join(parts) + '\n')  # 保证每行以换行符结尾

# 将修改后的内容保存到新文件，保持换行符
modified_file_path = 'modified_article_links2_with_newlines.txt'
with open(modified_file_path, 'w') as file:
    file.writelines(modified_lines)  # 使用 writelines 写入列表

