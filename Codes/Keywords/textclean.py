# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : textclean.py
# @Project  : PMonitor
# Time      : 2023/12/3 15:02
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from gensim.models.phrases import Phrases, Phraser


def read_and_preprocess(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        text_content = file.read()
        preprocessed_text = preprocess_text(text_content)
        return preprocessed_text

def load_stop_words():
    stop_words = list()
    with open("../../archive/en_stopwords.txt", 'r', encoding='utf-8') as file:
        for line in file:
            stop_words.append(line.strip())
    return stop_words


def train_phraser():
    txt_files = os.listdir("maltext")
    texts_list = []
    for file in txt_files:
        with open(f"maltext/{file}", "r", encoding="utf-8") as f:
            texts_list.append(f.read().strip())
    tokenized_texts = [word_tokenize(text.lower()) for text in texts_list]
    phrases = Phrases(tokenized_texts, min_count=1, threshold=2)
    bigram = Phraser(phrases)
    return bigram


def preprocess_text(html_content):
    # 移除代码段
    text_content = re.sub(r'(?s)\{.*?\}', ' ', html_content)  # 移除大括号包围的代码
    text_content = re.sub(r'(?s)\<.*?\>', ' ', text_content)  # 移除尖括号包围的代码

    # 保留以字母开头的单词，其中可能包含数字和特定符号
    words = nltk.word_tokenize(text_content)
    filtered_words = []
    for word in words:
        if re.match(r'^[a-zA-Z][a-zA-Z0-9@/_-]*$', word):
            filtered_words.append(word)

    clean_text = ' '.join(filtered_words)

    # 删除除字母、数字、空格、@、/、-、_ 以外的所有字符
    clean_text = re.sub(r'[^a-zA-Z0-9\s@\/\-_]', ' ', clean_text)
    # 分词
    tokens = nltk.word_tokenize(clean_text)
    # 应用短语模型
    # bigram = train_phraser()
    # tokens = bigram[tokens]
    # 去除停用词
    stop_words = set(stopwords.words('english'))
    stop_words.update(load_stop_words())
    tokens = [word for word in tokens if word.lower() not in stop_words]
    # 词形还原
    lemmatizer = WordNetLemmatizer()
    lemmatized_tokens = [lemmatizer.lemmatize(word) for word in tokens]

    return ' '.join(lemmatized_tokens)