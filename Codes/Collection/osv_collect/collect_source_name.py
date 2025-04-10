import requests

GITHUB_TOKEN = ''


# 获取 GitHub 上某个目录的文件列表
def get_directory_files(github_repo_url):
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.get(github_repo_url, headers=headers)
    response.raise_for_status()  # 确保请求成功
    return response.json()


# 处理恶意包数据，采集源和包名
def collect_malicious_packages():
    base_url = "https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious"
    output_lines = []

    # 获取所有源文件夹（如 npm, crates-io 等）
    source_folders = get_directory_files(base_url)

    for source_folder in source_folders:
        source_folder_name = source_folder["name"]
        source_folder_url = source_folder["url"]

        # 如果当前项是文件夹，则继续处理
        if source_folder["type"] == "dir":
            print(f"Processing source folder: {source_folder_name}")

            # 获取当前源文件夹下的所有包文件夹（即恶意包名称）
            package_folders = get_directory_files(source_folder_url)

            for package_folder in package_folders:
                package_folder_name = package_folder["name"]

                # 将源名和包名按要求格式添加到输出列表
                line = f"{source_folder_name}\t{package_folder_name}"
                output_lines.append(line)

    # 将采集到的源和包名保存到 txt 文件
    with open("source_name.txt", "w", encoding="utf-8") as out_file:
        out_file.write("\n".join(output_lines) + "\n")

    print("Processing complete. Results saved to malicious_packages.txt.")


# 执行采集
if __name__ == "__main__":
    collect_malicious_packages()
