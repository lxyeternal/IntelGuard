# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : reddit_collect.py
# @Project  : SCC_Intelligence
# Time      : 19/4/24 5:06 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import csv
import praw
from datetime import datetime


class RedditCollect:
    def __init__(self):
        # 认证信息
        self.client_id = ''
        self.client_secret = ''
        self.username = 'iBlueair'
        self.password = ''
        # 初始化 praw 实例
        self.reddit = praw.Reddit(
            client_id=self.client_id,  # 替换为你的客户端ID
            client_secret=self.client_secret,  # 替换为你的客户端密钥
            user_agent='SCC'  # 替换为你的用户代理字符串
        )
        self.post_link_list = []

    def post_links(self):
        with open('pagelinks/malicious-Reddit-Search.csv', 'r') as f:
            csvreader = csv.reader(f)
            # 跳过第一行
            next(csvreader)
            for row in csvreader:
                url = row[1]
                self.post_link_list.append(url)

    def post_collect(self):
        self.post_links()
        for url in self.post_link_list:
            print(url)
            # 通过ID获取帖子
            submission = self.reddit.submission(url=url)
            print(submission)
            # 打印帖子的标题和内容
            print('Title:', submission.title)
            print('Text:', submission.selftext)
            # 打印所有顶级评论
            # 打印帖子的创建时间
            created_time = datetime.utcfromtimestamp(submission.created_utc)
            print('Created at:', created_time.strftime('%Y-%m-%d %H:%M:%S UTC'))  # 格式化日期时间
            # 打印所有顶级评论
            submission.comments.replace_more(limit=50)
            for comment in submission.comments.list():
                print('Comment:', comment.body)


    def post_search(self):
        # 指定搜索的子版块
        subreddit = self.reddit.subreddit('Python')
        # 搜索关键词
        query = 'malicious'
        # 执行搜索
        search_results = subreddit.search(query, sort='Relevance', limit=100)  # 你可以调整 sort 和 limit 参数
        # 遍历搜索结果，打印每个帖子的标题和链接
        for post in search_results:
            post_url = post.url
            post_title = post.title
            created_time = datetime.utcfromtimestamp(post.created_utc)  # 将 Unix 时间戳转换为 UTC datetime
            print(post_title)  # 打印帖子的标题
            print(post_url)
            print(created_time)  # 打印帖子的创建时间




if __name__ == '__main__':
    reddit = RedditCollect()
    reddit.post_collect()
    # reddit.post_search()