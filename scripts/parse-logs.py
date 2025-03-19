import re
import argparse
from collections import Counter, defaultdict

def parse_log_line(line):
    log_pattern = re.compile(r'(?P<remote_host>\S+) \S+ \S+ \[.*?\] "\S+ (?P<resource>\S+) .*?" (?P<status_code>\d+) (?P<bytes>\d+|-)')
    match = log_pattern.match(line)
    if match:
        return {
            'remote_host': match.group('remote_host'),
            'resource': match.group('resource'),
            'status_code': int(match.group('status_code')),
            'bytes': int(match.group('bytes')) if match.group('bytes') != '-' else 0
        }
    return None

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
    
    most_requested_resource, most_requested_count = resource_counter.most_common(1)[0]
    most_active_host, most_host_requests = host_counter.most_common(1)[0]
    
    print(f"Total requests: {total_requests}")
    print(f"Total data transmitted: {total_bytes} bytes")
    print(f"Most requested resource: {most_requested_resource} ({most_requested_count} requests, {most_requested_count / total_requests * 100:.2f}%)")
    print(f"Remote host with most requests: {most_active_host} ({most_host_requests} requests, {most_host_requests / total_requests * 100:.2f}%)")
    print("Status code distribution:")
    for code_class in range(1, 6):
        percentage = (status_counter[code_class] / total_requests * 100) if total_requests else 0
        print(f"  {code_class}xx: {percentage:.2f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Apache log file")
    parser.add_argument('-f', '--file', required=True, help="Path to Apache log file")
    args = parser.parse_args()
    analyze_log(args.file)
