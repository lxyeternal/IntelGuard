# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : webpage_collection.py
# @Project  : PMonitor
# Time      : 22/1/24 9:33 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import csv
import praw
import time
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from Configs.config import HEADER
from datetime import datetime, timedelta
from selenium.webdriver.common.by import By
from selenium.common import NoSuchElementException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class WebPageCollection:
    def __init__(self):
        current_dir = os.path.dirname(__file__)
        codes_dir = os.path.dirname(current_dir)
        project_dir = os.path.dirname(codes_dir)
        self.bleepingcomputer = "https://www.bleepingcomputer.com/tag/pypi/page/{}/"
        self.medium = "https://medium.com/checkmarx-security"
        self.sonatype = "https://www.sonatype.com/blog?category=all&type=blog&page={}#resource-grid"
        self.checkmarx = "https://checkmarx.com/blog/"
        self.socket = "https://socket.dev/blog"
        self.github = "https://github.com/advisories?page={}&query=type%3Amalware"
        self.jfrog = "https://jfrog.com/blog"
        self.tuxcare = "https://tuxcare.com/blog/"
        self.datadoghq = "https://securitylabs.datadoghq.com/articles"
        self.qianxin = "https://tianwen.qianxin.com/blog/page/{}/"
        self.phylum = "https://blog.phylum.io/page/{}/"
        self.snyk = "https://snyk.io/blog/?page={}&tag=open-source-security"
        self.reversinglabs = "https://www.reversinglabs.com/blog/tag/appsec-supply-chain-security/page/{}/"
        self.checkpoint = "https://research.checkpoint.com/intelligence-reports/page/{}/"
        self.fortinet = "https://www.fortinet.com/blog/threat-research"
        self.securityaffairs = "https://securityaffairs.com/tag/npm/page/{}"
        self.rhisac = "https://rhisac.org/blog/page/{}/"
        self.collected_webpage_txt = "./pagelinks/collected_pagelinks.txt"
        self.waiting_webpage_txt = "./pagelinks/waiting_collection.txt"
        self.old_webpage_dict = {}
        self.chromedriver = os.path.join(project_dir, "Utils/chromedriver/macarm/chromedriver")
        self.service = Service(executable_path=self.chromedriver)
        self.options = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(service=self.service, options=self.options)

    def load_old_webpages(self):
        with open(self.waiting_webpage_txt) as txtfile:
            urlslist = txtfile.readlines()
            for url in urlslist:
                url_split = url.split("\t")
                source = url_split[-3].strip()
                page_url = url_split[-1].strip()
                if source in self.old_webpage_dict:
                    self.old_webpage_dict[source].append(page_url)
                else:
                    self.old_webpage_dict[source] = [page_url]

    def get_unique_timestamp(self):
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{timestamp}"
        return filename

    def convert_date_format(self, date_string):
        try:
            try:  # 尝试按照格式"%b %d, %Y"（缩写月份）解析日期字符串
                date_obj = datetime.strptime(date_string, "%b %d, %Y")
            except:  # 如果上述格式不匹配，则尝试按照格式"%B %d, %Y"（全称月份）解析
                date_obj = datetime.strptime(date_string, "%B %d, %Y")
            # 如果日期字符串成功解析，格式化日期对象为"%Y-%m-%d"格式的字符串
            formatted_date = date_obj.strftime("%Y-%m-%d")
            return formatted_date
        except (IndexError, ValueError):
            # 如果日期字符串不符合任何预期格式，返回"None"
            return "None"


    def write_txt(self, source, datetime, pageurl):
        timestamp = self.get_unique_timestamp()
        with open(self.waiting_webpage_txt, "a", encoding="utf-8") as txtfile:
            txtfile.write(timestamp + "\t" + source + "\t" + datetime + "\t" + pageurl + "\n")

    def bleepingcomputer_blog(self):
        for page_index in range(1, 3):
            if page_index == 1:
                pageurl = "https://www.bleepingcomputer.com/tag/pypi/"
            else:
                pageurl = self.bleepingcomputer.format(page_index)
            self.driver.get(pageurl)
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.ID, "bc-home-news-main-wrap")))
            self.driver.execute_script("window.stop();")  # 立即停止加载其余部分
            bc_latest_news = self.driver.find_element(By.ID, "bc-home-news-main-wrap")
            bc_latest_news_imgs = bc_latest_news.find_elements(By.CLASS_NAME, "bc_latest_news_text")
            for li_tag in bc_latest_news_imgs:
                li_url = li_tag.find_elements(By.TAG_NAME, "a")[0].get_attribute("href").strip()
                datetime_str = li_tag.find_element(By.CLASS_NAME, "bc_news_date").text.strip()
                formatted_date = self.convert_date_format(datetime_str.lower())
                if li_url not in self.old_webpage_dict.get("bleepingcomputer_oss", []):
                    self.write_txt("bleepingcomputer_oss", formatted_date, li_url)
                    print("bleepingcomputer_oss", formatted_date, li_url)

    def medium_blog(self):
        # 使用selenium的driver打开Medium网站
        self.driver.get(self.medium)
        # 模拟滚动到页面底部的JavaScript代码，以加载更多文章
        for _ in range(10):  # 滚动10次到页面底部
            self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")  # 执行滚动到页面底部的脚本
            time.sleep(2)  # 每次滚动后等待2秒，以便页面内容加载

        # 使用CSS选择器查找包含新闻的所有元素
        news_rows = self.driver.find_element(By.CSS_SELECTOR, ".in.x")
        n_p_elements = news_rows.find_elements(By.CSS_SELECTOR, ".n.p")

        for news_row in n_p_elements:
            # 获取新闻链接的href属性
            try:
                target_element = news_row.find_element(By.CSS_SELECTOR, ".mf.m.x")
                div_with_data_href = target_element.find_element(By.CSS_SELECTOR, 'div[data-href]')
                news_href = div_with_data_href.get_attribute('data-href')
                # 去除可能存在的查询参数，只保留基本的URL
                # news_href = news_href.split("?source")[0].strip()
                # 获取新闻发布日期的字符串，有的是 Aug 7，有的是 Oct 12, 2023 注意要规范化
                datetime_label = div_with_data_href.find_element(By.CSS_SELECTOR, ".li.n.lj.cr .n.o")
                span_element = datetime_label.find_element(By.TAG_NAME, 'span')
                datetime_str0 = span_element.text
                # 格式化日期
                if "days ago" in datetime_str0 or "d ago" in datetime_str0:
                    days_ago = int(datetime_str0.split()[0])
                    specific_date = datetime.now() - timedelta(days=days_ago)
                    formatted_date = specific_date.strftime('%Y-%m-%d')
                else:
                    try:
                        # 处理格式如 "Feb 1" 的日期，将其转换为今年的日期
                        specific_date = datetime.strptime(datetime_str0, '%b %d')
                        specific_date = specific_date.replace(year=datetime.now().year)
                        formatted_date = specific_date.strftime('%Y-%m-%d')
                    except ValueError:
                        try:
                            # 处理格式如 "Sep 24, 2023" 的日期
                            specific_date = datetime.strptime(datetime_str0, '%b %d, %Y')
                            formatted_date = specific_date.strftime('%Y-%m-%d')
                        except ValueError:
                            # 处理其他格式的日期
                            formatted_date = self.convert_date_format(datetime_str0)
                # 如果新闻链接不在已记录的旧网页字典中
                if news_href not in self.old_webpage_dict.get("medium", []):
                    # 将日期和链接写入文本文件
                    self.write_txt("medium", formatted_date, news_href)
                    # 打印日志信息
                    print("medium", formatted_date, news_href)
            except:
                pass


    def medium_recommand(self):
        page_url = "https://medium.com/tag/supply-chain-security/recommended"
        self.driver.get(page_url)
        self.driver.implicitly_wait(10)
        for count in range(20):
            self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)
        news_blogs = self.driver.find_elements(By.CSS_SELECTOR, ".jc.l")
        for news_blog in news_blogs:
            news_url_div = news_blog.find_element(By.CSS_SELECTOR, ".l.es.jy")
            news_url = news_url_div.find_element(By.TAG_NAME, "a").get_attribute("href").strip().split("?source")[0].strip()
            # datetime_str = news_blog.find_element(By.CSS_SELECTOR, ".lg.lh.li.lj.lk.ab.q").text.strip()
            datetime_str = news_blog.find_element(By.CSS_SELECTOR, ".lr.ab.dv.ae").text.strip()
            datetime_str_split = datetime_str.split("\n")[0].strip().lower()
            # 判断日期格式并转换
            if "days ago" in datetime_str_split or "d ago" in datetime_str_split:
                days_ago = int(datetime_str_split.split()[0])
                specific_date = datetime.now() - timedelta(days=days_ago)
                formatted_date = specific_date.strftime('%Y-%m-%d')
            else:
                try:
                    # 处理格式如 "Feb 1" 的日期，将其转换为今年的日期
                    specific_date = datetime.strptime(datetime_str_split, '%b %d')
                    specific_date = specific_date.replace(year=datetime.now().year)
                    formatted_date = specific_date.strftime('%Y-%m-%d')
                except ValueError:
                    try:
                        # 处理格式如 "Sep 24, 2023" 的日期
                        specific_date = datetime.strptime(datetime_str_split, '%b %d, %Y')
                        formatted_date = specific_date.strftime('%Y-%m-%d')
                    except ValueError:
                        # 处理其他格式的日期
                        formatted_date = self.convert_date_format(datetime_str_split)
            if news_url not in self.old_webpage_dict.get("medium_recommand", []):
                self.write_txt("medium_recommand", formatted_date, news_url)
                print("medium_recommand", formatted_date, news_url)

    def sonatype_blog(self):
        # 循环遍历全部的14页博客
        for page_index in range(1, 15):
            # 构造当前页面的URL
            page_url = self.sonatype.format(page_index)
            # 发送HTTP GET请求获取页面内容
            response = requests.get(page_url, headers=HEADER)
            # 使用BeautifulSoup解析HTML页面
            soup = BeautifulSoup(response.text, 'html.parser')
            # 定位博客文章区域
            blog_section = soup.find(class_='resources mt-5')
            # 查找所有博客文章卡片
            row_fluids = blog_section.find_all(class_='resource-card col-12 col-md-12 col-lg-4 mb-3')

            for row_fluid in row_fluids:
                resource_body = row_fluid.find(class_="resource-body card-body-grid flex-grow-1 d-lg-flex flex-column justify-content-between")
                text = resource_body.find(class_="resource-title h4 my-3")
                a_tag = text.find('a')
                href_value = a_tag.get('href')  # 找到帖子链接
                formatted_date = "None"
                # 如果找到链接并且链接不在已记录的旧网页字典中
                if a_tag:
                    href_value = a_tag.get('href')
                    if href_value not in self.old_webpage_dict.get("sonatype", []):
                        # 将日期、链接写入文本文件
                        self.write_txt("sonatype", formatted_date, href_value)
                        # 打印日志信息
                        print("sonatype", formatted_date, href_value)
                # 如果没有找到链接，不做任何操作
                else:
                    pass

    def sonatype_oss_blog(self):
        blog_url = "https://www.sonatype.com/blog/tag/everything-open-source?category=all&type=blog&page={}#resource-grid"
        for page_index in range(15):
            page_url = blog_url.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            row_fluids = soup.find(class_='resources mt-5')
            others = row_fluids.find_all(class_='resource-card col-12 col-md-12 col-lg-4 mb-3')
            rows = row_fluids.find_all(class_='row')
            for row_fluid in others:
                try:
                    link_div = row_fluid.find(class_="resource-title h4 my-3")
                    href_value = link_div.find('a').get('href')
                    if href_value not in self.old_webpage_dict.get("sonatype_oss", []):
                        self.write_txt("sonatype_oss", "None", href_value)
                        print("sonatype_oss", "None", href_value)
                except:
                    pass


    def checkmarx_blog(self):
        self.driver.get(self.checkmarx)
        # 模拟滚动到页面底部的JavaScript代码
        for _ in range(30):
            try:
                # 等待并点击“加载更多”按钮
                load_more_link = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.CSS_SELECTOR, ".pagination-show-more a")))
                # 将页面滚动到"Next"按钮所在的位置
                self.driver.execute_script("arguments[0].scrollIntoView();", load_more_link)
                # 尝试使用JavaScript触发点击事件
                self.driver.execute_script("arguments[0].click();", load_more_link)
                time.sleep(2)  # 给页面时间加载新内容
            except Exception as e:
                print(f"未找到'加载更多'链接或点击失败: {str(e)}")
                break  # 如果链接不存在或点击失败，则退出循环
        time.sleep(5)
        premium_blog_posts = self.driver.find_elements(By.CSS_SELECTOR, ".card-post.card-post__second-version.card-post__v4")
        for premium_blog_post in premium_blog_posts:
            premium_blog_entry_title = premium_blog_post.find_element(By.CLASS_NAME, "card-post__description")
            news_href = premium_blog_post.find_element(By.TAG_NAME, "a").get_attribute("href").strip()
            datetime_str = premium_blog_post.find_element(By.CLASS_NAME, "card-post__title").text.strip().lower()
            formatted_date = self.convert_date_format(datetime_str)
            if news_href not in self.old_webpage_dict.get("checkmarx", []):
                self.write_txt("checkmarx", formatted_date, news_href)
                print("checkmarx", formatted_date, news_href)


    def socket_blog(self):
        response = requests.get(self.socket, headers=HEADER)
        soup = BeautifulSoup(response.text, 'html.parser')
        css_vql929 = soup.find("div", class_="css-1vql929")
        chakra_linkbox = css_vql929.find_all("article", class_="chakra-linkbox")
        for linkbox in chakra_linkbox:
            css_rqbta = linkbox.find("div", class_="css-rqbta8")
            date_str = css_rqbta.find_all("span")[-1].text.strip().replace("-", "").strip().lower()
            formatted_date = self.convert_date_format(date_str)
            chakra_heading = linkbox.find("h3", class_="chakra-heading")
            href_div = chakra_heading.find("a", class_="chakra-linkbox__overlay")
            href_value = href_div.get('href')
            full_link = "https://socket.dev" + href_value
            if full_link not in self.old_webpage_dict.get("socket", []):
                self.write_txt("socket", formatted_date, full_link)
                print("socket", formatted_date, full_link)


    def github_blog(self):
        for page_index in range(1, 30):
            page_url = self.github.format(page_index)
            self.driver.get(page_url)
            time.sleep(5)
            self.driver.implicitly_wait(10)
            navigation_container = self.driver.find_element(By.CLASS_NAME, "js-active-navigation-container")
            navigation_items = navigation_container.find_elements(By.CLASS_NAME, "js-navigation-item")
            for navigation_item in navigation_items:
                datetime = navigation_item.find_element(By.TAG_NAME, "relative-time").get_attribute("datetime")
                href_value = navigation_item.find_element(By.TAG_NAME, "a").get_attribute("href")
                if href_value not in self.old_webpage_dict.get("github", []):
                    self.write_txt("github", datetime, href_value)
                    print("github", datetime, href_value)


    def jfrog_blog(self):
        self.driver.get(self.jfrog)
        self.driver.implicitly_wait(10)
        posts_wrap = self.driver.find_element(By.CLASS_NAME, "posts-wrap")
        blog_posts = posts_wrap.find_elements(By.CSS_SELECTOR, ".col-md-6.blog-post-title")
        self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        count = 0
        # while True:
        while count < 50:
            try:
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                # 查找"Next"按钮并等待它可点击
                next_button = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.CSS_SELECTOR, ".next a")))
                # 将页面滚动到"Next"按钮所在的位置
                self.driver.execute_script("arguments[0].scrollIntoView();", next_button)
                # 尝试使用JavaScript触发点击事件
                self.driver.execute_script("arguments[0].click();", next_button)
                time.sleep(10)
                # 等待新页面加载完成
                WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "posts-wrap")))
                posts_wrap = self.driver.find_element(By.CLASS_NAME, "posts-wrap")
                blog_posts = posts_wrap.find_elements(By.CSS_SELECTOR, ".col-md-6.blog-post-title")
                count += 1
                for blog_post in blog_posts:
                    post_date = blog_post.find_element(By.CLASS_NAME, "blog-post-date").text.split()[:3]
                    date_str = ' '.join(post_date).lower()
                    formatted_date = self.convert_date_format(date_str)
                    blog_post_link = blog_post.find_element(By.TAG_NAME, "a").get_attribute("href")
                    if blog_post_link not in self.old_webpage_dict.get("jfrog", []):
                        self.write_txt("jfrog", formatted_date, blog_post_link)
                        print("jfrog", formatted_date, blog_post_link)
            except NoSuchElementException:
                print("找不到'Next'按钮,可能已到达最后一页")
                break
            except Exception as e:
                print(f"发生错误: {str(e)}")
                break


    def datadoghq_blog(self):
        self.driver.get(self.datadoghq)
        while True:
            try:
                WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "ais-InfiniteHits-loadMore")))
                more_button = self.driver.find_element(By.CLASS_NAME, "ais-InfiniteHits-loadMore")
                more_button.click()
                self.driver.implicitly_wait(5)
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(2)
            except:
                break
        time.sleep(2)
        InfiniteHits_item = self.driver.find_elements(By.CLASS_NAME, "ais-InfiniteHits-item")
        for item in InfiniteHits_item:
            datetime_str = item.find_elements(By.CLASS_NAME, "hit-header-text")[1].text.strip().lower()
            formatted_date = self.convert_date_format(datetime_str)
            hit_title = item.find_element(By.CLASS_NAME, "hit-title-link").get_attribute("href")
            if hit_title not in self.old_webpage_dict.get("datadoghq", []):
                self.write_txt("datadoghq", formatted_date, hit_title)
                print("datadoghq", formatted_date, hit_title)


    def qianxin_blog(self):
        for page_index in range(1, 13):
            if page_index == 1:
                page_url = "https://tianwen.qianxin.com/blog/"
            else:
                page_url = self.qianxin.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            recent_post_items = soup.find_all("article", class_="recent-post-item")
            for item in recent_post_items:
                formatted_date = item.find('time', class_='time').get('datetime')
                formatted_date = formatted_date.split("T")[0]
                href_value = item.find("a", class_="title").get('href')
                full_link = "https://tianwen.qianxin.com" + href_value
                if full_link not in self.old_webpage_dict.get("qianxin", []):
                    self.write_txt("qianxin", formatted_date, full_link)
                    print("qianxin", formatted_date, full_link)


    def snyk_blog(self):
        for page_index in range(1, 28):
            page_url = self.snyk.format(page_index)
            resource = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(resource.text, 'html.parser')
            news_container = soup.find("div", class_="brandui-container")
            news_blogs = news_container.find_all('div', attrs={'data-component': 'Media Card'})
            for news_blog in news_blogs:
                datetime_str = news_blog.find("p", class_="txt-body txt-color-body txt-line-clamp-4").text.strip().lower()
                formatted_date = self.convert_date_format(datetime_str)
                news_href = news_blog.find("a", class_="group txt-decoration-none").get('href')
                full_link = "https://snyk.io" + news_href
                if full_link not in self.old_webpage_dict.get("snyk", []):
                    self.write_txt("snyk", formatted_date, full_link)
                    print("snyk", formatted_date, full_link)

    def securityaffairs_blog(self):
        for page_index in range(1, 3):
            page_url = self.securityaffairs.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            latest_news_block = soup.find("div", class_="latest-news-block")
            article_rows = latest_news_block.find_all("div", class_="news-card news-card-category mb-3 mb-lg-5")
            for article in article_rows:
                post_time = article.find("div", class_="post-time mb-3")
                datetime_str = post_time.find_all("span")[1].text.strip().lower()
                formatted_date = self.convert_date_format(datetime_str)
                article_link = article.find("a").get('href')
                if article_link not in self.old_webpage_dict.get("securityaffairs", []):
                    self.write_txt("securityaffairs", formatted_date, article_link)
                    print("securityaffairs", formatted_date, article_link)


    def fortinet_blog(self):
        self.driver.get(self.fortinet)
        flag = 30
        while flag:
            flag -= 1
            try:
                WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "b3-blog-list__pagination")))
                more_button = self.driver.find_element(By.CLASS_NAME, "btn")
                more_button.click()
                self.driver.implicitly_wait(5)
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(2)
            except:
                break
        time.sleep(2)
        InfiniteHits_item = self.driver.find_elements(By.CSS_SELECTOR, ".b3-blog-list__post.text-container")
        for item in InfiniteHits_item:
            hit_title = item.find_element(By.CLASS_NAME, "b3-blog-list__background").find_element(By.TAG_NAME, "a").get_attribute("href")
            b3_blog_list__meta = item.find_element(By.CLASS_NAME, "b3-blog-list__meta")
            datetime_str = b3_blog_list__meta.find_elements(By.TAG_NAME, "span")[1].text.strip().lower()
            formatted_date = self.convert_date_format(datetime_str)
            if hit_title not in self.old_webpage_dict.get("fortinet", []):
                self.write_txt("fortinet", formatted_date, hit_title)
                print("fortinet", formatted_date, hit_title)


    def phylum_blog(self):
        for page_index in range(1, 28):
            page_url = self.phylum.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            latest_news_block = soup.find_all("article", class_=["post tag-research", "post tag-insights", "post tag-research featured"])
            for article in latest_news_block[1:]:
                article_link = article.find("a", class_="post-title-link").get('href')
                formatted_date = article.find("time").get('datetime')
                full_link = "https://blog.phylum.io" + article_link
                if full_link not in self.old_webpage_dict.get("phylum", []):
                    self.write_txt("phylum", formatted_date, full_link)
                    print("phylum", formatted_date, full_link)


    def reversinglabs_blog(self):
        for page_index in range(1, 24):
            page_url = self.reversinglabs.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            blog__listing_item = soup.find("div", class_="blog__listing-item")
            article_rows = blog__listing_item.find_all("article", class_="blog__item")
            for article in article_rows:
                datetime_str = article.find("time").get('datetime')
                article_link = article.find("a").get('href')
                if article_link not in self.old_webpage_dict.get("reversinglabs", []):
                    self.write_txt("reversinglabs", datetime_str, article_link)
                    print("reversinglabs", datetime_str, article_link)


    def tuxcare_blog(self):
        self.driver.get(self.tuxcare)
        time.sleep(2)
        InfiniteHits_item = self.driver.find_element(By.CLASS_NAME, "blog-posts")
        posts = InfiniteHits_item.find_elements(By.CLASS_NAME, "post")
        for item in posts:
            hit_title = item.find_element(By.TAG_NAME, "a").get_attribute("href")
            post_date_element = item.find_element(By.CLASS_NAME, "post-date").find_element(By.TAG_NAME, "span")
            datetime_str = post_date_element.get_attribute('outerHTML').replace('<span>', '').replace('</span>', '')
            date_obj = datetime.strptime(datetime_str, "%B %d, %Y")
            formatted_date = date_obj.strftime("%Y-%m-%d")
            if hit_title not in self.old_webpage_dict.get("tuxcare", []):
                self.write_txt("tuxcare", formatted_date, hit_title)
                print("tuxcare", formatted_date, hit_title)

    def cybersecuritynews_blog(self):
        for page_index in range(1, 2):
            for package_manage in ["npm", "pypi"]:
                page_url = "https://cybersecuritynews.com/page/{}/?s={}".format(page_index, package_manage)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            latest_news_block = soup.find_all("div", class_="td_module_16 td_module_wrap td-animation-stack")
            for article in latest_news_block:
                post_date = article.find("span", class_="td-post-date").find("time").get('datetime')
                parsed_date = datetime.strptime(post_date, "%Y-%m-%dT%H:%M:%S%z")
                # 转换为所需格式
                formatted_date = parsed_date.strftime("%Y-%m-%d")
                article_link = article.find("a").get('href')
                if article_link not in self.old_webpage_dict.get("cybersecuritynews", []):
                    self.write_txt("cybersecuritynews", str(formatted_date), article_link)
                    print("cybersecuritynews", str(formatted_date), article_link)

    def rhisac_blog(self):
        for page_index in range(1, 83):
            page_url = self.rhisac.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            latest_news_block = soup.find_all("article", class_="post inner-row")
            for article in latest_news_block:
                article_link = article.find("a").get('href').strip()
                datetime_text = article.find("p", class_="mb-0").text.strip().replace("Posted on ", "").strip().lower()
                formatted_date = self.convert_date_format(datetime_text)
                if article_link not in self.old_webpage_dict.get("rhisac", []):
                    self.write_txt("rhisac", formatted_date, article_link)
                    print("rhisac", formatted_date, article_link)



    def checkpoint_blog(self):
        for page_index in range(1, 81):
            page_url = self.checkpoint.format(page_index)
            response = requests.get(page_url, headers=HEADER)
            soup = BeautifulSoup(response.text, 'html.parser')
            latest_news_block = soup.find_all("div", class_="box col-margin relative border-dotted")
            for article in latest_news_block:
                post_date = article.find("div", class_="date small-font").text.strip()
                formatted_date = self.convert_date_format(post_date)
                article_link = article.find("a").get('href')
                if article_link not in self.old_webpage_dict.get("checkpoint", []):
                    print("checkpoint", formatted_date, article_link)
                    self.write_txt("checkpoint", formatted_date, article_link)


    def reddit_blog(self):
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
        # 指定搜索的子版块
        subreddit = self.reddit.subreddit('Python')
        # 搜索关键词
        query = 'malicious'
        # 执行搜索
        search_results = subreddit.search(query, sort='Relevance', limit=200)  # 你可以调整 sort 和 limit 参数
        # 遍历搜索结果，打印每个帖子的标题和链接
        for post in search_results:
            post_url = post.url
            post_title = post.title
            created_time = datetime.utcfromtimestamp(post.created_utc)  # 将 Unix 时间戳转换为 UTC datetime
            formatted_date = created_time.strftime('%Y-%m-%d')  # 格式化日期
            if post_url not in self.old_webpage_dict.get("reddit", []):
                self.write_txt("reddit", formatted_date, post_url)
                print("reddit", formatted_date, post_url)



if __name__ == '__main__':
    webpagecollection = WebPageCollection()
    webpagecollection.load_old_webpages()
    # webpagecollection.snyk_blog()
    # webpagecollection.qianxin_blog()
    # webpagecollection.datadoghq_blog()
    # webpagecollection.jfrog_blog()
    # webpagecollection.github_blog()
    # webpagecollection.medium_recommand()
    # webpagecollection.medium_blog()
    # webpagecollection.checkmarx_blog()
    # webpagecollection.sonatype_oss_blog()
    # webpagecollection.sonatype_blog()
    webpagecollection.bleepingcomputer_blog()
    # webpagecollection.securityaffairs_blog()
    # webpagecollection.fortinet_blog()
    # webpagecollection.phylum_blog()
    # webpagecollection.reversinglabs_blog()
    # webpagecollection.tuxcare_blog()
    # webpagecollection.cybersecuritynews_blog()
    # webpagecollection.rhisac_blog()
    # webpagecollection.socket_blog()
    # webpagecollection.checkpoint_blog()
    # webpagecollection.reddit_blog()