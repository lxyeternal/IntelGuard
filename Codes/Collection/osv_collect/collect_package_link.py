import requests
from bs4 import BeautifulSoup


# 读取源文件并获取源和包名
def read_source_name_file(file_path):
    source_names = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            source, package = line.strip().split("\t")
            source_names.append((source, package))
    return source_names


# 读取已采集的包名
def read_collected_packages(output_file):
    collected_packages = set()
    try:
        with open(output_file, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    collected_packages.add(parts[1])  # 只记录包名
    except FileNotFoundError:
        pass  # 如果文件不存在，表示还没有采集数据
    return collected_packages


# 定义源名称转换规则
def get_transformed_source(source):
    source_mapping = {
        # "go": "golang",
        # "maven": "maven",
        # "npm": "npm",
        # "nuget": "nuget",
        "pypi": "pip",
        "rubygems": "rubygems"
    }

    # 如果是 crates-io，直接跳过不访问
    if source == "crates-io" or source == "go" or source == "maven" or source == "npm" or source == "nuget":
        return None

    # 获取转换后的源名，如果不存在则保持原名
    return source_mapping.get(source, source)


# 访问指定的Snyk URL并解析网页内容
def fetch_snyk_data(source, package):
    transformed_source = get_transformed_source(source)
    if transformed_source is None:
        return []  # 如果源是 crates-io，返回空列表

    url = f"https://security.snyk.io/vuln/{transformed_source}?search={package}"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # 确保请求成功
    return response.text


# 解析网页并提取符合条件的记录
def extract_malicious_package_links(html, source, package):
    soup = BeautifulSoup(html, 'html.parser')

    # 检查页面中是否包含 "No results found" 文本
    if "No results found" in soup.get_text():  # 获取页面的全部文本并检查是否包含该文本
        print(f"No results found for {source} - {package}")
        return None  # 如果页面无结果，则跳过该包

    tbody = soup.find('tbody', class_='table__tbody')

    # 查找符合条件的行
    for row in tbody.find_all('tr', class_='table__row'):
        # 查找第一个包含Malicious Package的元素
        elem1 = row.find('td', class_='table__data-cell--first-column')

        # 查找第二个包含包名的元素
        # elem2 = row.find_all('td', class_='table__data-cell--first-row')[1] or row.find_all('td', class_='table__data-cell')[1]
        # 安全地获取第二个td元素，检查是否有足够的元素
        try:
            elem2 = row.find_all('td', class_='table__data-cell--first-row')[1]  # 尝试找第一个匹配
        except IndexError:
            elem2 = row.find_all('td', class_='table__data-cell')[1] if len(
                row.find_all('td', class_='table__data-cell')) > 1 else None  # 如果没有找到，尝试第二个

        if elem1 and elem2:
            link = elem1.find('a')['href']  # 获取元素1的链接
            vul_type = elem1.find('a').text.strip()  # 是否为 Malicious Package
            found_package = elem2.find('a').text.strip()  # 获取元素2的包名

            if vul_type == "Malicious Package" and found_package == package:
                full_link = f"https://security.snyk.io{link}"
                return f"{source}\t{package}\t{full_link}"

    return None


# 主函数，执行爬取任务
def collect_malicious_package_links(source_name_file, output_file):
    source_names = read_source_name_file(source_name_file)

    # 读取已采集的数据
    collected_packages = read_collected_packages(output_file)

    processed_sources = set()

    # 遍历所有源和包
    for source, package in source_names:
        if source not in processed_sources:
            print(f"starting to process source: {source}")
            processed_sources.add(source)

        # 如果包已经采集过，则跳过
        if package in collected_packages:
            print(f"Skipping already collected package: {package}")
            continue

        try:
            # 获取网页内容
            html = fetch_snyk_data(source, package)
            if html:
                # 提取符合条件的链接
                link = extract_malicious_package_links(html, source, package)
                if link:
                    with open(output_file, 'a', encoding='utf-8') as out_file:
                        out_file.write(link + '\n')
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {source} - {package}: {e}")

    print("Processing complete. Results saved to", output_file)


# 执行
if __name__ == "__main__":
    collect_malicious_package_links("source_name.txt", "malicious_package_links.txt")
