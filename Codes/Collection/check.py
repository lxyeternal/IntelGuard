def compare_contents(collected_file, waiting_file):
    # 读取 collected_pagelinks.txt 文件内容
    with open(collected_file, 'r', encoding='utf-8') as f:
        collected_lines = f.readlines()

    # 读取 waiting_collection_new.txt 文件内容
    with open(waiting_file, 'r', encoding='utf-8') as f:
        waiting_lines = f.readlines()

    # 提取 collected_pagelinks.txt 中的所有具体内容（第一个字段）及其对应的源（第二个字段）
    collected_contents = {line.split('\t')[0]: line.split('\t')[1] for line in collected_lines}

    # 按源分组，存储每个源的缺失内容
    missing_by_source = {}
    # 按源分组，存储每个源的总内容条数
    total_by_source = {}

    # 检查 waiting_collection_new.txt 中的每个具体内容是否在 collected_contents 中
    for line in waiting_lines:
        waiting_content = line.split('\t')[0]
        waiting_source = line.split('\t')[1]

        # 统计每个源的总内容条数
        if waiting_source not in total_by_source:
            total_by_source[waiting_source] = 0
        total_by_source[waiting_source] += 1

        if waiting_content not in collected_contents or collected_contents[waiting_content] != waiting_source:
            if waiting_source not in missing_by_source:
                missing_by_source[waiting_source] = []
            missing_by_source[waiting_source].append(waiting_content)

    # 打印缺失内容，按源分组
    for source, missing_contents in missing_by_source.items():
        if source == 'reddit' or source == 'github':
            continue
        for content in missing_contents:
            print(f"Source '{source}'  Content '{content}'")

    # 打印每个源的总内容条数和缺失数目
    print("\nSummary of contents by source:")
    for source, total_count in total_by_source.items():
        if source == 'reddit' or source == 'github':
            continue
        missing_count = len(missing_by_source.get(source, []))
        print(f"'{source}': {missing_count} / {total_count}")


if __name__ == '__main__':
    # 调用函数
    compare_contents('pagelinks/collected_pagelinks.txt', 'pagelinks/waiting_collection_new.txt')


'''
Summary of contents by source:
'qianxin': 6 / 56  'NoneType' object has no attribute 'find_all'
'jfrog': 45 / 658  无效链接 404 This frog is in the dark
'securityweek': 194 / 196  需要人机验证
'''