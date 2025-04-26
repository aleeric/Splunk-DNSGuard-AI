#!/usr/bin/env python3
import csv
import datetime
import ipaddress
import json
import math
import os
import random
import string
import time
from collections import defaultdict

# Configuration parameters
MAX_EVENTS = 1000000  # Maximum number of events to generate (under 1 million)
OUTPUT_FILE = "dns_events.json"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
TIME_PERIOD_DAYS = 30  # 1 month of data

# Organization infrastructure simulation
NUM_INTERNAL_HOSTS = 100  # Realistic number of hosts in a medium-sized organization
LINUX_HOSTS_PERCENTAGE = 20  # 20% of hosts are Linux servers
TOTAL_ANOMALIES = 10  # Total number of anomalies to distribute

# Domain lists
TOP_DOMAINS = [
    "google.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "apple.com",
    "netflix.com",
    "salesforce.com",
    "zoom.us",
    "office365.com",
    "github.com",
    "slack.com",
    "linkedin.com",
    "dropbox.com",
    "tableau.com",
    "adobe.com",
    "akamai.net",
    "cloudflare.com",
    "fastly.net",
    "adobe.io",
    "windows.net",
    "digicert.com",
    "azurewebsites.net",
    "shopify.com",
    "adobedtm.com",
]

MALICIOUS_DOMAINS = [
    "evil-c2-server.com",
    "malware-payload.net",
    "data-exfil.org",
    "cryptominer.biz",
    "fakeupdates.xyz",
    "command-cntr.info",
    "ransomware-delivery.co",
    "steal-credentials.net",
    "backdoor-access.org",
    "trojan-updates.com",
    "malicious-cdn.net",
    "exploit-kit.xyz",
]

RECORD_TYPES = {
    "A": 60,  # 60% probability
    "AAAA": 15,  # 15% probability
    "MX": 5,  # 5% probability
    "TXT": 3,  # 3% probability
    "CNAME": 10,  # 10% probability
    "NS": 4,  # 4% probability
    "PTR": 2,  # 2% probability
    "ANY": 1,  # 1% probability
}

RARE_RECORD_TYPES = ["SPF", "SRV", "DNSKEY", "NSEC", "NSEC3", "HINFO", "AXFR"]

REPLY_CODES = {
    "NOERROR": 0.975,  # 97.5% successful queries
    "NXDOMAIN": 0.02,  # 2% domain not found
    "SERVFAIL": 0.004,  # 0.4% server failure
    "REFUSED": 0.001,  # 0.1% query refused
}

# Departmental segmentation for more realistic network simulation
DEPARTMENTS = [
    {"name": "IT", "subnet": "10.1.1.0/24", "host_count": 15, "query_rate_range": (20, 150)},
    {"name": "Engineering", "subnet": "10.1.2.0/24", "host_count": 25, "query_rate_range": (15, 120)},
    {"name": "Sales", "subnet": "10.1.3.0/24", "host_count": 20, "query_rate_range": (10, 80)},
    {"name": "Marketing", "subnet": "10.1.4.0/24", "host_count": 15, "query_rate_range": (10, 90)},
    {"name": "Finance", "subnet": "10.1.5.0/24", "host_count": 10, "query_rate_range": (5, 70)},
    {"name": "HR", "subnet": "10.1.6.0/24", "host_count": 5, "query_rate_range": (5, 60)},
    {"name": "Servers", "subnet": "10.2.0.0/24", "host_count": 10, "query_rate_range": (50, 250)},
]

# Define workday patterns for realistic activity cycles
WORKDAY_HOURS = {
    0: 0.1,  # 12am: 10% of normal activity (maintenance, etc)
    1: 0.05, # 1am: 5% of normal activity
    2: 0.05, # 2am: 5% of normal activity
    3: 0.05, # 3am: 5% of normal activity
    4: 0.1,  # 4am: 10% of normal activity
    5: 0.2,  # 5am: 20% of normal activity
    6: 0.3,  # 6am: 30% of normal activity
    7: 0.6,  # 7am: 60% of normal activity
    8: 0.9,  # 8am: 90% of normal activity
    9: 1.0,  # 9am: 100% of normal activity (peak)
    10: 1.0, # 10am: 100% of normal activity
    11: 1.0, # 11am: 100% of normal activity
    12: 0.8, # 12pm: 80% of normal activity (lunch)
    13: 0.9, # 1pm: 90% of normal activity
    14: 1.0, # 2pm: 100% of normal activity
    15: 1.0, # 3pm: 100% of normal activity
    16: 1.0, # 4pm: 100% of normal activity
    17: 0.8, # 5pm: 80% of normal activity
    18: 0.5, # 6pm: 50% of normal activity
    19: 0.3, # 7pm: 30% of normal activity
    20: 0.2, # 8pm: 20% of normal activity
    21: 0.2, # 9pm: 20% of normal activity
    22: 0.15, # 10pm: 15% of normal activity
    23: 0.1, # 11pm: 10% of normal activity
}

WEEKEND_HOURS = {hour: rate * 0.3 for hour, rate in WORKDAY_HOURS.items()}

# Anomaly types that match the detection methods in Splunk
ANOMALY_TYPES = [
    "C2_TUNNELING",        # High volume of DNS queries
    "BEACONING",           # Regular, periodic queries
    "BURST_ACTIVITY",      # Sudden spikes in query volume
    "TXT_RECORD_ANOMALY",  # Unusual use of TXT records
    "ANY_RECORD_ANOMALY",  # Reconnaissance using ANY queries
    "HINFO_RECORD_ANOMALY", # Reconnaissance using HINFO queries
    "AXFR_RECORD_ANOMALY", # Reconnaissance using AXFR queries
    "QUERY_LENGTH_ANOMALY", # Unusually long queries
    "DOMAIN_SHADOWING",    # Many unique subdomains
    "BEHAVIORAL_CLUSTER"   # Similar abnormal DNS behavior
]

# Generate internal hosts based on departmental structure
def generate_internal_hosts():
    hosts = []
    
    # Generate hosts for each department
    for dept in DEPARTMENTS:
        subnet = ipaddress.ip_network(dept["subnet"])
        ip_list = list(subnet.hosts())
        
        for i in range(min(dept["host_count"], len(ip_list))):
            ip = str(ip_list[i])
            
            # Determine OS type
            if dept["name"] == "Servers":
                os_type = "linux" if random.random() < 0.8 else "windows"  # 80% Linux servers
                hostname_prefix = f"{random.choice(['srv', 'app', 'db', 'web', 'api'])}"
                hostname = f"{hostname_prefix}-{random.randint(100, 999)}.internal"
            else:
                os_type = "linux" if random.random() < (LINUX_HOSTS_PERCENTAGE / 100) else "windows"
                if os_type == "windows":
                    hostname_prefix = f"{random.choice(['WSTN', 'USRPC', 'LAPTOP'])}"
                    hostname = f"{hostname_prefix}-{dept['name']}-{random.randint(1000, 9999)}"
                else:
                    hostname_prefix = f"{random.choice(['ws', 'pc', 'lt'])}"
                    hostname = f"{hostname_prefix}-{dept['name'].lower()}-{random.randint(100, 999)}"
            
            # Query rate varies by department and has day/night patterns
            min_rate, max_rate = dept["query_rate_range"]
            query_rate = random.randint(min_rate, max_rate)
            
            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "os": os_type,
                "department": dept["name"],
                "query_rate": query_rate
            })
    
    return hosts


# Generate subdomains for a given domain
def generate_subdomain(domain, length=None, entropy="normal"):
    if length is None:
        if entropy == "normal":
            length = random.randint(1, 3)  # Normal subdomains are relatively short
        elif entropy == "high":
            length = random.randint(3, 8)  # More complex subdomains for shadowing/malicious
        elif entropy == "extreme":
            length = random.randint(5, 15)  # Extremely long for data exfiltration

    subdomain_parts = []
    for _ in range(length):
        if entropy == "normal":
            # Normal subdomains often have meaningful words
            part_options = [
                "www", "mail", "ftp", "smtp", "pop", "api", "cdn", "dev", "test", "prod",
                "stage", "uat", "auth", "login", "secure", "shop", "store", "blog", "docs",
                "support", "help", "admin", "portal", "mobile", "app", "m", "vpn", "remote"
            ]
            if random.random() < 0.7 and part_options:  # 70% chance of using common subdomain
                part = random.choice(part_options)
            else:
                part_length = random.randint(3, 8)
                part = "".join(
                    random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                    for _ in range(part_length)
                )
        elif entropy == "high":
            # High entropy subdomains have more randomness
            part_length = random.randint(8, 15)
            part = "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                for _ in range(part_length)
            )
        elif entropy == "extreme":
            # Extreme entropy subdomains for data exfiltration
            part_length = random.randint(30, 60)
            part = "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                for _ in range(part_length)
            )

        subdomain_parts.append(part)

    return ".".join(subdomain_parts) + "." + domain


# Generate normal DNS event with more realistic patterns
def generate_normal_dns_event(host, timestamp):
    # Select domain based on a realistic distribution (frequent sites more common)
    domain_weights = [100, 90, 85, 80, 75, 70, 65, 60, 55, 50, 45, 40, 35, 30, 25, 20, 15, 10, 5, 5, 5, 5, 5, 5]
    domain = random.choices(TOP_DOMAINS[:len(domain_weights)], weights=domain_weights[:len(TOP_DOMAINS)], k=1)[0]

    # Query pattern based on host type and time of day
    is_server = host["department"] == "Servers"
    
    # Servers more likely to query direct domains and have consistent patterns
    if is_server:
        if random.random() < 0.9:  # 90% direct domain for servers
            query = domain
        else:
            query = generate_subdomain(domain)
    else:
        if random.random() < 0.7:  # 70% direct domain for workstations
            query = domain
        else:
            query = generate_subdomain(domain)

    # Choose record type based on weighted probabilities
    record_type = random.choices(
        list(RECORD_TYPES.keys()), weights=list(RECORD_TYPES.values()), k=1
    )[0]

    # Select reply code based on weighted probabilities
    reply_code = random.choices(
        list(REPLY_CODES.keys()), weights=list(REPLY_CODES.values()), k=1
    )[0]

    # Set answer based on reply code and record type
    answer = None
    if reply_code == "NOERROR":
        if record_type == "A":
            answer = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        elif record_type == "AAAA":
            answer = f"2001:db8::{random.randint(1, 9999):x}"
        elif record_type == "MX":
            answer = f"{random.randint(10, 30)} mail{random.randint(1, 5)}.{domain}"
        elif record_type == "CNAME":
            answer = f"cdn{random.randint(1, 10)}.{domain}"
        elif record_type == "TXT":
            answer = f"v=spf1 include:{domain} ~all"
        elif record_type == "NS":
            answer = f"ns{random.randint(1, 5)}.{domain}"
        elif record_type == "PTR":
            answer = f"{random.choice(['mail', 'www', 'ftp'])}.{domain}"
        elif record_type == "ANY":
            answer = "Multiple records returned"

    # Select a DNS server - Most companies have 2-3 internal DNS servers
    dns_servers = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    dns_server = random.choice(dns_servers)

    # Generate DNS event following Splunk's CIM for Network Resolution
    event = {
        "timestamp": timestamp.strftime(TIMESTAMP_FORMAT),
        "source": "dns",
        "sourcetype": "dns",
        "host": host["hostname"],
        # CIM fields for DNS
        "src": host["ip"],
        "src_host": host["hostname"],
        "dest_port": 53,
        "dest": dns_server,  # Internal DNS server
        "record_type": record_type,
        "query": query,
        "answer": answer,
        "message_type": "QUERY",
        "reply_code": reply_code,
        "user": f"user_{host['department'].lower()}_{random.randint(1, 50)}",  # Department-based user
        "duration": random.uniform(0.001, 0.05),  # Query duration in seconds
        "transport": "UDP" if random.random() < 0.95 else "TCP",
        "vendor_product": "Microsoft DNS" if host["os"] == "windows" else "BIND",
        "department": host["department"]  # Adding department info for analysis
    }

    return event


# Anomaly generation functions - updated to match Splunk detection methods

# 1. C2 Tunneling - High volume of DNS queries
def generate_c2_tunneling(base_host, start_time, num_events=200):
    """
    Generate events with anomalously high query volumes
    This simulates Command and Control or data exfiltration
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)

    # This will generate a higher than normal volume of DNS queries in a short period
    # Typically happens over several hours to evade simple rate-based detection
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 4),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)
        
        # C2 traffic has distinct patterns
        event["query"] = generate_subdomain(c2_domain, entropy="high")
        event["record_type"] = random.choices(
            ["A", "AAAA", "TXT"],
            weights=[60, 20, 20],
            k=1
        )[0]
        
        event["anomaly_type"] = "C2_TUNNELING"
        events.append(event)

    return events

# 2. Beaconing Detection - Regular, periodic DNS queries 
def generate_beaconing(base_host, start_time, num_events=60, interval_minutes=15):
    """
    Create events at very regular intervals (beaconing)
    This simulates Command and Control communication with an infection
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)

    # Create events at regular intervals with small jitter (typical of C2)
    for i in range(num_events):
        # Add a small jitter (±10 seconds) to the regular interval
        jitter = random.uniform(-10, 10)
        timestamp = start_time + datetime.timedelta(
            minutes=(i * interval_minutes),
            seconds=jitter
        )

        event = generate_normal_dns_event(host, timestamp)
        event["query"] = generate_subdomain(c2_domain, entropy="high")
        
        # Most beaconing uses A records, but may occasionally use others
        event["record_type"] = "A" if random.random() < 0.9 else "TXT"
        
        event["anomaly_type"] = "BEACONING"
        events.append(event)

    return events

# 3. Burst Activity Detection - Sudden spikes in query volume
def generate_burst_activity(base_host, start_time, num_events=150):
    """
    Generate a burst of events in a very short time period
    This simulates sudden malicious activity or data exfiltration
    """
    events = []
    host = base_host.copy()

    # Generate a burst of events in a short time period (30 seconds)
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(seconds=random.uniform(0, 30))
        event = generate_normal_dns_event(host, timestamp)
        
        # During a burst, various domains may be queried
        if random.random() < 0.3:  # 30% chance of querying suspicious domains
            event["query"] = generate_subdomain(random.choice(MALICIOUS_DOMAINS), entropy="high")
        
        event["anomaly_type"] = "BURST_ACTIVITY"
        events.append(event)

    return events

# 4. TXT Record Anomaly Detection - Unusual use of TXT records
def generate_txt_record_anomaly(base_host, start_time, num_events=40):
    """
    Generate excessive use of TXT records
    This simulates Command and Control or data exfiltration via DNS
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 8),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "TXT"
        event["query"] = generate_subdomain(c2_domain, entropy="high")

        # Simulate encoded data in TXT record (base64-like)
        data_length = random.randint(30, 200)
        event["answer"] = "\"" + "".join(
            random.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
            )
            for _ in range(data_length)
        ) + "\""
        
        event["anomaly_type"] = "TXT_RECORD_ANOMALY"
        events.append(event)

    return events

# 5. ANY Record Anomaly Detection - Reconnaissance using ANY queries
def generate_any_record_anomaly(base_host, start_time, num_events=25):
    """
    Generate excessive use of ANY records
    This often indicates reconnaissance activity or amplification attacks
    """
    events = []
    host = base_host.copy()

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 6),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "ANY"
        
        # Often targeting specific domains during recon
        domains_of_interest = random.sample(TOP_DOMAINS, min(5, len(TOP_DOMAINS)))
        event["query"] = random.choice(domains_of_interest)
        
        event["anomaly_type"] = "ANY_RECORD_ANOMALY"
        events.append(event)

    return events

# 6. HINFO Record Anomaly Detection - Reconnaissance using HINFO queries
def generate_hinfo_record_anomaly(base_host, start_time, num_events=20):
    """
    Generate use of HINFO record types for reconnaissance
    This can indicate attempts to gather system information
    """
    events = []
    host = base_host.copy()

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 4),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "HINFO"
        
        # Targeting various domains to gather host information
        event["query"] = random.choice(TOP_DOMAINS)
        
        event["anomaly_type"] = "HINFO_RECORD_ANOMALY"
        events.append(event)

    return events

# 7. AXFR Record Anomaly Detection - Reconnaissance using AXFR queries
def generate_axfr_record_anomaly(base_host, start_time, num_events=15):
    """
    Generate use of AXFR record types for zone transfer attempts
    This can indicate reconnaissance or information gathering
    """
    events = []
    host = base_host.copy()

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 3),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "AXFR"
        
        # Typically targeting key domains for zone transfer
        targeted_domains = random.sample(TOP_DOMAINS, min(3, len(TOP_DOMAINS)))
        event["query"] = random.choice(targeted_domains)
        
        # Most AXFR requests will be refused
        event["reply_code"] = "REFUSED" if random.random() < 0.9 else "NOERROR"
        
        event["anomaly_type"] = "AXFR_RECORD_ANOMALY"
        events.append(event)

    return events

# 8. Query Length Anomaly Detection - Unusually long DNS queries
def generate_query_length_anomaly(base_host, start_time, num_events=30):
    """
    Generate unusually long DNS queries
    This often indicates data exfiltration via DNS tunneling
    """
    events = []
    host = base_host.copy()
    tunnel_domain = random.choice(MALICIOUS_DOMAINS)

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 6),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)

        # Generate an extremely long DNS query (data exfiltration)
        event["query"] = generate_subdomain(tunnel_domain, entropy="extreme")
        
        # Query length anomalies often use A records to blend in
        event["record_type"] = "A" if random.random() < 0.7 else "TXT"
        
        event["anomaly_type"] = "QUERY_LENGTH_ANOMALY"
        events.append(event)

    return events

# 9. Domain Shadowing Detection - Many unique subdomains
def generate_domain_shadowing(base_host, start_time, num_events=45):
    """
    Generate many unique subdomains for a legitimate domain
    This simulates domain shadowing attacks
    """
    events = []
    host = base_host.copy()
    target_domain = random.choice(TOP_DOMAINS)

    # Generate many unique, random subdomains for the same parent domain
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 12),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        event = generate_normal_dns_event(host, timestamp)

        # Generate a unique random subdomain with high entropy
        event["query"] = generate_subdomain(target_domain, entropy="high")
        
        # Usually A records pointing to malicious IPs
        event["record_type"] = "A"
        
        # Shadow domains often resolve to suspicious IPs
        if event["reply_code"] == "NOERROR":
            # Generate suspicious-looking IPs
            suspicious_ranges = ["185.220.", "45.95.", "91.219."]
            suspicious_prefix = random.choice(suspicious_ranges)
            event["answer"] = f"{suspicious_prefix}{random.randint(0, 255)}.{random.randint(1, 255)}"
        
        event["anomaly_type"] = "DOMAIN_SHADOWING"
        events.append(event)

    return events

# 10. Behavioral Clustering - Similar abnormal DNS behavior across hosts
def generate_behavioral_cluster(base_hosts, start_time, cluster_size=3, event_count=40):
    """
    Create a group of hosts with similar abnormal DNS behavior
    This helps demonstrate behavioral clustering for anomaly detection
    """
    all_events = []

    # Select hosts for this cluster
    cluster_hosts = random.sample(base_hosts, min(cluster_size, len(base_hosts)))

    # Define a consistent pattern for this cluster
    cluster_domain = random.choice(MALICIOUS_DOMAINS)
    cluster_record_type = random.choice(["A", "TXT"])
    query_interval = random.randint(10, 30)  # minutes

    # Give them similar behavior patterns
    for host in cluster_hosts:
        for i in range(event_count):
            timestamp = start_time + datetime.timedelta(
                minutes=i * query_interval + random.uniform(-2, 2)  # Similar timing
            )
            
            event = generate_normal_dns_event(host, timestamp)
            event["query"] = generate_subdomain(cluster_domain, entropy="high")
            event["record_type"] = cluster_record_type
            
            # Consistent pattern in answers for this botnet/cluster
            if event["record_type"] == "TXT":
                # Encoded command pattern unique to this cluster
                prefix = "".join(random.choices("abcdef0123456789", k=6))
                data_length = random.randint(20, 40)
                payload = "".join(
                    random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=")
                    for _ in range(data_length)
                )
                event["answer"] = f"\"{prefix}{payload}\""
            
            event["anomaly_type"] = "BEHAVIORAL_CLUSTER"
            all_events.append(event)

    return all_events

# Helper function to generate normal baseline activity for all hosts with realistic patterns
def generate_baseline_activity(hosts, start_time, end_time, max_events):
    """
    Generate baseline normal DNS activity for all hosts for the entire time period
    with realistic daily and weekly patterns
    """
    events = []
    total_events = 0
    
    # Calculate the total duration in hours
    duration_hours = int((end_time - start_time).total_seconds() / 3600)
    
    print(f"Generating baseline activity for {len(hosts)} hosts over {duration_hours} hours...")
    
    # Track number of events per host for reporting
    host_event_counts = defaultdict(int)

    # For each hour in the time period
    for hour_offset in range(duration_hours):
        current_hour = start_time + datetime.timedelta(hours=hour_offset)
        hour_of_day = current_hour.hour
        is_weekend = current_hour.weekday() >= 5  # 5=Saturday, 6=Sunday
        
        # Get the appropriate activity multiplier based on hour and day type
        if is_weekend:
            activity_multiplier = WEEKEND_HOURS[hour_of_day]
        else:
            activity_multiplier = WORKDAY_HOURS[hour_of_day]
            
        # For each host, generate normal queries for this hour
        for host in hosts:
            # Servers have more consistent activity patterns (less affected by business hours)
            if host["department"] == "Servers":
                server_multiplier = activity_multiplier * 0.5 + 0.5  # Minimum 50% activity for servers
                queries_this_hour = max(1, int(host["query_rate"] * server_multiplier * random.uniform(0.8, 1.2)))
            else:
                queries_this_hour = max(1, int(host["query_rate"] * activity_multiplier * random.uniform(0.7, 1.3)))
            
            # Generate events for this host for this hour
            for _ in range(queries_this_hour):
                # Check if we've reached the maximum events limit
                if total_events >= max_events:
                    print(f"Reached maximum events limit ({max_events})")
                    return events, host_event_counts
                    
                # Random time within this hour
                event_time = current_hour + datetime.timedelta(
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )

                # Create the normal DNS event
                event = generate_normal_dns_event(host, event_time)
                events.append(event)
                host_event_counts[host["hostname"]] += 1
                total_events += 1

    print(f"Generated {total_events} baseline events")
    return events, host_event_counts


def main():
    print(f"Generating DNS events over {TIME_PERIOD_DAYS} days following Splunk CIM for Network_Resolution...")

    # Generate the internal hosts
    internal_hosts = generate_internal_hosts()
    print(f"Generated {len(internal_hosts)} hosts across {len(DEPARTMENTS)} departments")

    # Set the time range (30 days back from now)
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=TIME_PERIOD_DAYS)

    # Create a list to store all events
    all_events = []

    # Define anomaly types mapping to generator functions
    anomaly_generators = {
        "C2_TUNNELING": generate_c2_tunneling,
        "BEACONING": generate_beaconing,
        "BURST_ACTIVITY": generate_burst_activity, 
        "TXT_RECORD_ANOMALY": generate_txt_record_anomaly,
        "ANY_RECORD_ANOMALY": generate_any_record_anomaly,
        "HINFO_RECORD_ANOMALY": generate_hinfo_record_anomaly,
        "AXFR_RECORD_ANOMALY": generate_axfr_record_anomaly,
        "QUERY_LENGTH_ANOMALY": generate_query_length_anomaly,
        "DOMAIN_SHADOWING": generate_domain_shadowing
    }
    
    # Set aside some percentage of the total events for anomalies (20%)
    baseline_max_events = int(MAX_EVENTS * 0.8)
    
    # Generate baseline normal activity for all hosts
    print("Generating baseline normal DNS activity...")
    baseline_events, host_event_counts = generate_baseline_activity(internal_hosts, start_time, end_time, baseline_max_events)
    all_events.extend(baseline_events)
    
    # Determine how to distribute the 10 anomalies
    # Strategy: 2 hosts with 3 anomalies each, 2 hosts with 2 anomalies each, 0 anomalies for the rest
    
    # Shuffle the hosts for random selection
    random.shuffle(internal_hosts)
    
    # Select hosts for anomalies (with preference for high-activity hosts)
    anomaly_hosts = sorted(internal_hosts[:10], key=lambda h: host_event_counts[h["hostname"]], reverse=True)
    
    # Distribute anomalies: 2 hosts with 3 anomalies, 2 hosts with 2 anomalies, 0 anomalies for rest
    host_anomaly_distribution = {
        anomaly_hosts[0]["hostname"]: 3,  # 3 anomalies for most active host
        anomaly_hosts[1]["hostname"]: 3,  # 3 anomalies for second most active host
        anomaly_hosts[2]["hostname"]: 2,  # 2 anomalies
        anomaly_hosts[3]["hostname"]: 2,  # 2 anomalies
    }
    
    print("\nAnomaly distribution:")
    for hostname, count in host_anomaly_distribution.items():
        print(f"  {hostname}: {count} anomalies")
    
    # Keep track of which host gets which anomaly
    host_anomaly_map = defaultdict(list)
    
    # List of anomalies we'll assign
    anomaly_types_to_assign = list(anomaly_generators.keys())
    random.shuffle(anomaly_types_to_assign)
    
    # Assign anomalies to hosts
    anomaly_count = 0
    for hostname, num_anomalies in host_anomaly_distribution.items():
        host = next(h for h in internal_hosts if h["hostname"] == hostname)
        
        for _ in range(num_anomalies):
            if anomaly_count >= TOTAL_ANOMALIES or not anomaly_types_to_assign:
                break
                
            anomaly_type = anomaly_types_to_assign.pop(0)
            host_anomaly_map[hostname].append(anomaly_type)
            
            # Generate a random time for this anomaly (avoid weekends for more realism)
            while True:
                random_day = random.randint(0, TIME_PERIOD_DAYS - 1)
                anomaly_time = start_time + datetime.timedelta(days=random_day)
                # Skip weekends for more realism (anomalies more common during workdays)
                if anomaly_time.weekday() < 5:  # 0-4 are Monday to Friday
                    break
                    
            # Add hour and minute
            anomaly_time += datetime.timedelta(
                hours=random.randint(8, 17),  # Business hours
                minutes=random.randint(0, 59)
            )
            
            # Generate the anomaly events
            generator_func = anomaly_generators[anomaly_type]
            anomaly_events = generator_func(host, anomaly_time)
            all_events.extend(anomaly_events)
            
            print(f"Generated {len(anomaly_events)} events for {anomaly_type} on host {hostname}")
            anomaly_count += 1
    
    # Handle behavioral clustering separately (needs multiple hosts)
    # Select 3 random hosts that don't already have anomalies
    non_anomalous_hosts = [h for h in internal_hosts if h["hostname"] not in host_anomaly_map]
    if len(non_anomalous_hosts) >= 3:
        cluster_hosts = random.sample(non_anomalous_hosts, 3)
        
        # Record these hosts as part of the behavioral cluster
        for host in cluster_hosts:
            host_anomaly_map[host["hostname"]].append("BEHAVIORAL_CLUSTER")
        
        # Generate a random time for behavioral clustering (workday)
        while True:
            random_day = random.randint(0, TIME_PERIOD_DAYS - 1)
            anomaly_time = start_time + datetime.timedelta(days=random_day)
            if anomaly_time.weekday() < 5:  # Weekday
                break
                
        # Add hour and minute
        anomaly_time += datetime.timedelta(
            hours=random.randint(8, 17),  # Business hours
            minutes=random.randint(0, 59)
        )
        
        # Generate the behavioral clustering events
        cluster_events = generate_behavioral_cluster(
            cluster_hosts,
            anomaly_time,
            cluster_size=len(cluster_hosts),
            event_count=30
        )
        all_events.extend(cluster_events)
        print(f"Generated {len(cluster_events)} events for Behavioral Cluster across {len(cluster_hosts)} hosts")
    
    # Sort all events by timestamp
    print("Sorting events by timestamp...")
    all_events.sort(key=lambda x: x["timestamp"])
    
    # Write events to file in JSON format
    print(f"Writing {len(all_events)} events to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")
    
    # Create a summary file with details about the anomalies
    with open("dns_events_summary.txt", "w") as f:
        f.write(f"Total DNS events generated: {len(all_events)}\n")
        f.write(f"Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Count events by anomaly type
        anomaly_counts = defaultdict(int)
        normal_count = 0
        
        for event in all_events:
            if "anomaly_type" in event:
                anomaly_counts[event["anomaly_type"]] += 1
            else:
                normal_count += 1
                
        f.write("Event counts by type:\n")
        f.write(f"- Normal DNS events: {normal_count}\n")
        for anomaly_type, count in sorted(anomaly_counts.items()):
            f.write(f"- {anomaly_type}: {count} events\n")
            
        f.write("\nAnomalous hosts:\n")
        for hostname, anomaly_types in host_anomaly_map.items():
            host_info = next((h for h in internal_hosts if h["hostname"] == hostname), None)
            if host_info:
                anomalies_str = ", ".join(anomaly_types)
                f.write(f"{hostname} ({host_info['ip']}, {host_info['department']}): {anomalies_str}\n")
                
        f.write("\nDetection Methods (based on Splunk macros):\n")
        f.write("1. C2 Tunneling: `dns_c2_tunneling_detection` - High volume DNS queries\n")
        f.write("2. Beaconing: `dns_beaconing_detection` - Regular timing patterns\n")
        f.write("3. Burst Activity: `dns_burst_activity_detection` - Sudden query spikes\n")
        f.write("4. TXT Record Anomalies: `dns_txt_record_detection` - Unusual TXT record usage\n")
        f.write("5. ANY Record Anomalies: `dns_any_record_detection` - Reconnaissance with ANY queries\n")
        f.write("6. HINFO Record Anomalies: `dns_hinfo_record_detection` - Host info gathering\n")
        f.write("7. AXFR Record Anomalies: `dns_axfr_record_detection` - Zone transfer attempts\n")
        f.write("8. Query Length Anomalies: `dns_query_length_detection` - Data exfiltration via long queries\n")
        f.write("9. Domain Shadowing: `dns_domain_shadowing_detection` - Multiple unique subdomains\n")
        f.write("10. Behavioral Clustering: `dns_behavioral_clustering_detection` - Coordinated malicious activity\n")
        
    print(f"Generated {len(all_events)} DNS events and saved to {OUTPUT_FILE}")
    print(f"Summary saved to dns_events_summary.txt")


if __name__ == "__main__":
    main()
