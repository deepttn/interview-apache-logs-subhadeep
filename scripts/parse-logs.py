#!/usr/bin/env python3

import re
import argparse
import sqlite3
from collections import Counter, defaultdict

LOG_DB = "logs.db"
OUTPUT_FILE = "parsed_results.txt"

def parse_log_line(line):
    log_pattern = re.compile(
        r'(?P<remote_host>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<resource>\S+) (?P<protocol>HTTP/\d\.\d)" (?P<status_code>\d+) (?P<bytes>\d+|-) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
    )
    match = log_pattern.match(line)
    if match:
        return {
            'remote_host': match.group('remote_host'),
            'timestamp': match.group('timestamp'),
            'method': match.group('method'),
            'resource': match.group('resource'),
            'protocol': match.group('protocol'),
            'status_code': int(match.group('status_code')),
            'bytes': int(match.group('bytes')) if match.group('bytes') != '-' else 0,
            'referrer': match.group('referrer'),
            'user_agent': match.group('user_agent')
        }
    return None

def save_to_db(data):
    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_host TEXT,
            timestamp TEXT,
            method TEXT,
            resource TEXT,
            protocol TEXT,
            status_code INTEGER,
            bytes_sent INTEGER,
            referrer TEXT,
            user_agent TEXT
        )
    """)
    cursor.execute("""
        INSERT INTO log_analysis (remote_host, timestamp, method, resource, protocol, status_code, bytes_sent, referrer, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (data['remote_host'], data['timestamp'], data['method'], data['resource'], data['protocol'], data['status_code'], data['bytes'], data['referrer'], data['user_agent']))
    conn.commit()
    conn.close()

def analyze_log(file_path):
    total_requests = 0
    total_bytes = 0
    resource_counter = Counter()
    host_counter = Counter()
    status_counter = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                total_requests += 1
                total_bytes += parsed['bytes']
                resource_counter[parsed['resource']] += 1
                host_counter[parsed['remote_host']] += 1
                status_counter[parsed['status_code'] // 100] += 1
                save_to_db(parsed)  # Store each log in the database

    if total_requests == 0:
        print("No valid log entries found.")
        return

    most_requested_resource, most_requested_count = resource_counter.most_common(1)[0]
    most_active_host, most_host_requests = host_counter.most_common(1)[0]

    with open(OUTPUT_FILE, 'w') as out:
        out.write(f"Total requests: {total_requests}\n")
        out.write(f"Total data transmitted: {total_bytes} bytes\n")
        out.write(f"Most requested resource: {most_requested_resource} ({most_requested_count} requests, {most_requested_count / total_requests * 100:.2f}%)\n")
        out.write(f"Remote host with most requests: {most_active_host} ({most_host_requests} requests, {most_host_requests / total_requests * 100:.2f}%)\n")
        out.write("Status code distribution:\n")
        for code_class in range(1, 6):
            percentage = (status_counter[code_class] / total_requests * 100) if total_requests else 0
            out.write(f"  {code_class}xx: {percentage:.2f}%\n")

    print(f"Analysis saved to {OUTPUT_FILE}")
    print("Logs successfully saved to database.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Apache log file")
    parser.add_argument('-f', '--file', required=True, help="Path to Apache log file")
    args = parser.parse_args()
    analyze_log(args.file)
