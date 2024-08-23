import os


def process_txt_file(file_path):
    # 读取文件内容，指定UTF-8编码
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 删除前51行和最后35行
    # processed_lines = lines[51:-35]
    processed_lines = lines[4:]

    # 将处理后的内容写入同名文件（覆盖原文件），指定UTF-8编码
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(processed_lines)


def process_folder(folder_path):
    # 遍历文件夹中的所有文件
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.txt'):
            file_path = os.path.join(folder_path, file_name)
            # 处理每个txt文件
            process_txt_file(file_path)


# 指定fortinet文件夹的路径
# folder_path = 'fortinet'
folder_path = 'checkpoint'

# 处理fortinet文件夹中的所有txt文件
process_folder(folder_path)
