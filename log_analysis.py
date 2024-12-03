import re
from collections import defaultdict

#function to parse the log file and extract data
def parse_log_file(log_file):

    """
    The log file will be parsed to extract log entries.
    Returns a list of dictionaries containing:
    - IP Address
    - HTTP Method
    - Endpoint
    - Status Code

    """
    log_entries=[]
    log_pattern=re.compile(r'(?P<ip>[\d\.]+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>[^\s]+) HTTP/1.1" (?P<status>\d+)')
    
    with open(log_file,'r') as file:
        for line in file:
            match=log_pattern.match(line)
            if match:
                log_entries.append({
                    'ip':match.group('ip'),
                    'method':match.group('method'),
                    'endpoint':match.group('endpoint'),
                    'status':int(match.group('status'))
                })
    return log_entries

#function to count requests per ip
def count_requests(log_entries):

    """
    Counts the number of requests per IP address.
    Returns a sorted list of tuples: (IP Address, Request Count).

    """
    ip_counts=defaultdict(int)
    for entry in log_entries:
        ip_counts[entry['ip']]+=1
    return sorted(ip_counts.items(),key=lambda x:x[1],reverse=True)




log_file="sample.log"

#parse the log file
log_entries=parse_log_file(log_file)

#analyze the log entries to find count requests per ip,most frequently accessed endpoint and to detect suspicious activity
request_per_ip=count_requests(log_entries)

#Display the results
print("Requests per IP address :")
print(f"{'IP Address':<20} {'Request Count':<15}")
for ip,count in request_per_ip:
    print(f"{ip:<20} {count}")
