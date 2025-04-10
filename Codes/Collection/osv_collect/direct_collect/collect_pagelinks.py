import requests
from datetime import datetime

GITHUB_TOKEN = ''

# 获取当前时间戳
def get_unique_timestamp():
    current_time = datetime.now()
    timestamp = current_time.strftime("%Y%m%d_%H%M%S_%f")
    return timestamp


# 下载 GitHub 上的原始 JSON 文件
def download_json_file(url):
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # 确保请求成功
    return response.json()


# 获取 GitHub 上某个目录的文件列表
def get_directory_files(github_repo_url):
    # 获取 GitHub 仓库某个目录的文件列表
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.get(github_repo_url, headers=headers)
    response.raise_for_status()  # 确保请求成功
    return response.json()


# 处理 GitHub 上的 malicious 文件夹的 JSON 文件
def process_json_files():
    output_lines = []

    # GitHub 仓库的基础 URL 和目标目录
    base_url = "https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious"
    print("Starting to process the malicious packages...")

    # 获取源文件夹列表（如 npm, crates-io 等）
    source_folders = get_directory_files(base_url)
    print(f"Found {len(source_folders)} source folders in the repository.")

    for source_folder in source_folders:
        source_folder_name = source_folder["name"]
        source_folder_url = source_folder["url"]

        # 检查当前项是否为文件夹
        if source_folder["type"] != "dir":
            continue  # 如果是文件则跳过

        print(f"Processing source folder: {source_folder_name}")

        # 获取每个源文件夹下的文件或子文件夹
        package_folders = get_directory_files(source_folder_url)
        print(f"Found {len(package_folders)} package folders in source folder {source_folder_name}.")

        for package_folder in package_folders:
            package_folder_name = package_folder["name"]
            package_folder_url = package_folder["url"]
            # 获取该恶意包文件夹中的所有文件
            files = get_directory_files(package_folder_url)

            for file in files:
                # 只处理 JSON 文件
                if file["name"].endswith(".json"):
                    json_file_name = file["name"]
                    json_file_url = f"https://raw.githubusercontent.com/ossf/malicious-packages/main/osv/malicious/{source_folder_name}/{package_folder_name}/{json_file_name}"
                    print(f"Processing JSON file: {json_file_name} from source folder {source_folder_name}")

                    try:
                        json_data = download_json_file(json_file_url)

                        # 检查 references 字段中的 type 是否为 "ARTICLE"
                        if "references" in json_data:
                            for ref in json_data["references"]:
                                if ref.get("type") == "ARTICLE":
                                    # 提取信息
                                    timestamp = get_unique_timestamp()
                                    published = json_data.get("published", None)
                                    if published:
                                        # 只取日期部分
                                        published = published.split("T")[0]
                                    url = ref.get("url", None)

                                    # 格式化输出行
                                    line = f"{timestamp}\t{source_folder_name}\t{package_folder_name}\t{published}\t{url}"
                                    output_lines.append(line)
                    except requests.exceptions.RequestException as e:
                        print(f"Error downloading JSON file: {e}")

        # 在处理完每个源后，将当前的有效信息保存到文件
        with open("osc_pagelinks.txt", "a") as out_file:
            out_file.write("\n".join(output_lines) + "\n")
        # print(f"Processed source folder {source_folder_name}, results saved to osc_pagelinks.txt.")
        output_lines.clear()  # Clear the output_lines list for the next source folder

    print(f"Processing complete. Results saved to osc_pagelinks.txt.")


if __name__ == "__main__":
    # 直接调用处理函数
    process_json_files()
