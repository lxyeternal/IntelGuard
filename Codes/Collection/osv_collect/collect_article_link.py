import requests
from bs4 import BeautifulSoup


# 读取恶意包链接列表
def read_malicious_package_links(file_path):
    malicious_links = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            source, package, url = line.strip().split("\t")
            malicious_links.append((source, package, url))
    return malicious_links


# 读取已处理的包
def read_processed_packages(output_file):
    processed_packages = set()
    try:
        with open(output_file, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    processed_packages.add(parts[1])  # 只记录包名
    except FileNotFoundError:
        pass  # 如果文件不存在，表示还没有采集数据
    return processed_packages


# 访问链接并提取相关信息
def fetch_and_extract_references(url, source, package):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # 确保请求成功
        soup = BeautifulSoup(response.text, 'html.parser')

        # 检查页面是否包含 "References" 字样
        if "References" in soup.get_text():
            # 找到最后一个 class="markdown-section" 的元素
            markdown_section = soup.find_all(class_='markdown-section')[-1]

            # 查找这个 section 下的第一个 <a> 标签链接
            reference_link = markdown_section.find('a', href=True)
            if reference_link:
                # 返回格式为：源 包名称 链接
                return f"{source}\t{package}\t{reference_link['href']}"
        else:
            print(f"No references found for {source} - {package}.")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
    return None


# 主函数，执行采集任务
def collect_references(malicious_links_file, output_file):
    malicious_links = read_malicious_package_links(malicious_links_file)

    # 读取已处理包的集合
    processed_packages = read_processed_packages(output_file)

    processed_source = set()

    with open(output_file, 'a', encoding='utf-8') as out_file:
        for source, package, url in malicious_links:
            if source in ['npm', 'nuget', 'pypi']:  # added by gjj
                continue

            if source not in processed_source:
                print(f"Processing source: {source}")
                processed_source.add(source)

            # 检查包是否已处理过
            if package in processed_packages:
                print(f"Skipping already processed package: {source} - {package}")
                continue  # 跳过已处理的包

            result = fetch_and_extract_references(url, source, package)
            if result:
                out_file.write(result + "\n")
                processed_packages.add(package)  # 将已处理的包添加到集合中

    print(f"Processing complete. Results saved to {output_file}")


# 执行
if __name__ == "__main__":
    collect_references("malicious_package_links.txt", "article_links.txt")
