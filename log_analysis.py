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

#function to find most accessed endpoint
def find_endpoint(log_entries):

    """
    Finds the most accessed endpoint.
    Returns a tuple: (Endpoint, Count).

    """
    endpoint_counts=defaultdict(int)
    for entry in log_entries:
        endpoint_counts[entry['endpoint']]+=1
    most_accessed=max(endpoint_counts.items(),key=lambda x:x[1])
    return most_accessed

#function to detect suspicious activity
def detect_suspicious_activity(log_entries,threshold=10):

    """
    Detects suspicious activity by identifying IPs with failed login attempts.
    Only IPs with 'more' than 'threshold' failed login attempts will be returned.
    Returns a sorted list of tuples: (IP Address, Failed Login Count).

    """
    failed_attempts=defaultdict(int)
    for entry in log_entries:
        if entry['status'] == 401:  # HTTP 401 Unauthorized indicates a failed login attempt
            failed_attempts[entry['ip']] += 1
    suspicious_ips = [(ip, count) for ip, count in failed_attempts.items() if count > threshold]
    return sorted(suspicious_ips, key=lambda x: x[1], reverse=True)



#beginning of main()
log_file="sample.log"

#parse the log file
log_entries=parse_log_file(log_file)

#analyze the log entries to find count requests per ip,most frequently accessed endpoint
request_per_ip=count_requests(log_entries)
most_accessed_endpoint=find_endpoint(log_entries)

#Display the results
print("Requests per IP address :")
print(f"{'IP Address':<20} {'Request Count':<15}")
for ip,count in request_per_ip:
    print(f"{ip:<20} {count}")

print("\n Most frequently accessed Endpoint : ")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

#Taking user input for threshold (if needed) and analyzing suspicious activity based on threshold
reply=input("\n Do you want to enter threshold value to detect suspicious activity ? (y/n) (if no then default value of 10 will be used) : ")
if reply.lower()=='y':
    threshold=int(input("Enter threshold value to detect suspicious activity : "))
    suspicious_activity=detect_suspicious_activity(log_entries,threshold)
else:
    suspicious_activity=detect_suspicious_activity(log_entries) 

#Display the results
if suspicious_activity:
    print("\n Suspicious Activity Detected : ")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in suspicious_activity:
        print(f"{ip:<20} {count}")
else:
    print("\n No suspicious activity detected.")
        

