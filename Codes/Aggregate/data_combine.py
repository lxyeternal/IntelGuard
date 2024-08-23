# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : data_combine.py
# @Project  : SCC_Intelligence
# Time      : 5/5/24 3:49 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import csv
import json


def write_data(data, output_file):
    with open(output_file, "a", newline='') as csvfile:
        csvwriter = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(data)

def parse_bq_date():
    bq_date = {}
    with open("/Users/blue/Documents/GitHub/SCC_Intelligence/analysis_data/bq-results-pypi.json", "r") as f:
        f_lines = f.readlines()
        for f_line in f_lines:
            data = json.loads(f_line)
            pkgname = data.get("name", "").strip()
            version = data.get("version", "").strip()
            upload_time = data.get("upload_time", "").strip().split(" ")[0]
            if pkgname not in bq_date:
                bq_date[pkgname] = [[], []]  # Initialize the list of versions and upload times
            bq_date[pkgname][0].append(version)
            bq_date[pkgname][1].append(upload_time)
    for pkg in bq_date:
        # Convert lists to sets to remove duplicates, then convert back to lists
        bq_date[pkg][0] = list(set(bq_date[pkg][0]))
        bq_date[pkg][1] = list(set(bq_date[pkg][1]))
        # Sort the lists after removing duplicates
        bq_date[pkg][0].sort()
        bq_date[pkg][1].sort()
    output_file = "/Users/blue/Desktop/newnewtest.csv"
    with open("/Users/blue/Desktop/pypi_data.csv", "r") as csvfile:
        csvreader = csv.reader(csvfile)
        for index, row in enumerate(csvreader):
            row_filename = row[0].strip()
            if row_filename in ["pip", "cctx"]:
                continue
            if index == 0:  # Assuming the first row might be headers, skip processing but write the headers
                write_data(row + ["None"], output_file)
                continue
            if row_filename in bq_date:
                # Update the version field in the original row
                row[2] = ' '.join(bq_date[row_filename][0])  # Update version
                # Append the earliest upload time to the row
                earliest_upload_time = bq_date[row_filename][1][0]
                write_data(row + [earliest_upload_time], output_file)
            else:
                # Handle cases where no data is found
                write_data(row + ["None"], output_file)


def load_webpage():
    old_time_dict = {}
    new_time_dict = {}
    with open("/Users/blue/Documents/GitHub/SCC_Intelligence/codes/Collection/pagelinks/old_time_webpage.txt", "r") as csvfile:
        content_lines = csvfile.readlines()
        for index, row in enumerate(content_lines):
            row_split = row.strip().split("\t")
            source = row_split[1].lower()
            timedata = row_split[2]
            link = row_split[3]
            if source in old_time_dict:
                old_time_dict[source].append((len(old_time_dict[source]) + 1, timedata, link))
            else:
                old_time_dict[source] = [(1, timedata, link)]
    with open("/Users/blue/Documents/GitHub/SCC_Intelligence/codes/Collection/pagelinks/new_time_webpage.txt", "r") as csvfile:
        content_lines = csvfile.readlines()
        for index, row in enumerate(content_lines):
            row_split = row.strip().split("\t")
            timestamp = row_split[0]
            source = row_split[1].lower()
            timedata = row_split[2]
            link = row_split[3]
            if source in new_time_dict:
                new_time_dict[source].append((timestamp, timedata, link))
            else:
                new_time_dict[source] = [(timestamp, timedata, link)]
    with open("/Users/blue/Desktop/pypi_data_all.csv", "r") as f:
        csvreader = csv.reader(f)
        for line in csvreader:
            print(line)



if __name__ == '__main__':
    parse_bq_date()

