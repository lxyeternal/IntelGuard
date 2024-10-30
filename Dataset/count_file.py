import os
import json


def count_verify_gpt4_files(data_folder):
    data_folder = 'IntelliJson/' + data_folder
    verify_gpt4_count = 0  # 以 _verify_gpt4.json 结尾的文件数量
    empty_file_count = 0  # 空文件数量

    # 遍历数据文件夹中的所有文件
    for filename in os.listdir(data_folder):
        # 检查文件名是否以 _verify_gps4.json 结尾
        if filename.endswith('_verify_gpt4.json'):
            verify_gpt4_count += 1  # 符合条件的文件数量加1
            file_path = os.path.join(data_folder, filename)  # 获取文件的完整路径

            # 打开文件并读取内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()  # 去除内容前后的空白字符

                # 检查文件内容是否为空或是空的 JSON 对象
                if content == '' or content == '{}':
                    empty_file_count += 1  # 空文件数量加1
                else:
                    try:
                        json_data = json.loads(content)  # 解析 JSON 内容
                        # 检查 "package_name" 字段是否为空列表
                        if isinstance(json_data, dict) and json_data.get('package_name') == []:
                            empty_file_count += 1  # 空文件数量加1
                    except json.JSONDecodeError:
                        # 不是有效的 JSON 格式
                        print("not a valid json")

    print(f"{data_folder} total file: {verify_gpt4_count}")
    print(f"{data_folder} empty file: {empty_file_count}")
    return


count_verify_gpt4_files('checkmarx')
count_verify_gpt4_files('medium_recommand')
count_verify_gpt4_files('phylum')
count_verify_gpt4_files('sonatype_oss')

'''
IntelliJson/checkmarx total file: 242
IntelliJson/checkmarx empty file: 111
IntelliJson/medium_recommand total file: 85
IntelliJson/medium_recommand empty file: 21
IntelliJson/phylum total file: 97
IntelliJson/phylum empty file: 19
IntelliJson/sonatype_oss total file: 198
IntelliJson/sonatype_oss empty file: 128
'''