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
TOTAL_EVENTS = 1  # Increased for 90 days of data
OUTPUT_FILE = "dns_events.json"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
TIME_PERIOD_DAYS = 14  # Extended from 7 to 90 days

# Organization infrastructure simulation
NUM_INTERNAL_HOSTS = 25  # Number of internal hosts making DNS queries
LINUX_HOSTS_PERCENTAGE = 5  # Percentage of hosts that are Linux servers

# Anomaly configuration
NUM_ANOMALIES_PER_TYPE = 3  # Number of instances of each anomaly type to generate

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


# Generate internal hosts
def generate_internal_hosts(num_hosts, linux_percentage):
    hosts = []
    linux_hosts = int(num_hosts * linux_percentage / 100)
    windows_hosts = num_hosts - linux_hosts

    # Generate Windows hosts
    for i in range(windows_hosts):
        ip = f"10.1.{random.randint(0, 255)}.{random.randint(1, 254)}"
        hostname = f"WIN-{random.choice(['WSTN', 'USRPC', 'LAPTOP'])}-{random.randint(1000, 9999)}"
        hosts.append(
            {
                "ip": ip,
                "hostname": hostname,
                "os": "windows",
                "query_rate": random.randint(10, 100),  # Queries per hour (average)
            }
        )

    # Generate Linux hosts
    for i in range(linux_hosts):
        ip = f"10.2.{random.randint(0, 255)}.{random.randint(1, 254)}"
        hostname = (
            f"{random.choice(['srv', 'app', 'db', 'web'])}-{random.randint(100, 999)}"
        )
        hosts.append(
            {
                "ip": ip,
                "hostname": hostname,
                "os": "linux",
                "query_rate": random.randint(
                    20, 200
                ),  # Servers typically make more DNS queries
            }
        )

    return hosts


# Generate subdomains for a given domain
def generate_subdomain(domain, length=None, entropy="normal"):
    if length is None:
        if entropy == "normal":
            length = random.randint(1, 3)  # Normal subdomains are relatively short
        elif entropy == "high":
            length = random.randint(
                3, 8
            )  # More complex subdomains for shadowing/malicious
        elif entropy == "extreme":
            length = random.randint(5, 15)  # Extremely long for data exfiltration

    subdomain_parts = []
    for _ in range(length):
        if entropy == "normal":
            # Normal subdomains often have meaningful words
            part_options = [
                "www",
                "mail",
                "ftp",
                "smtp",
                "pop",
                "api",
                "cdn",
                "dev",
                "test",
                "prod",
                "stage",
                "uat",
            ]
            if (
                random.random() < 0.7 and part_options
            ):  # 70% chance of using common subdomain
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


# Generate normal DNS event
def generate_normal_dns_event(host, timestamp):
    domain = random.choice(TOP_DOMAINS)

    # 80% chance of querying the domain directly, 20% chance of querying a subdomain
    if random.random() < 0.8:
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
        "dest": f"10.0.0.{random.randint(1, 5)}",  # Internal DNS server
        "record_type": record_type,
        "query": query,
        "answer": answer,
        "message_type": "QUERY",
        "reply_code": reply_code,
        "user": f"user_{random.randint(1, 50)}",  # Random user
        "duration": random.uniform(0.001, 0.05),  # Query duration in seconds
        "transport": "UDP" if random.random() < 0.95 else "TCP",
        "vendor_product": "Microsoft DNS" if host["os"] == "windows" else "BIND",
    }

    return event


# Anomaly generation functions


# 1. Volume and Frequency Anomaly Detection
def generate_volume_anomaly(base_host, start_time, num_events=500):
    """
    Generate events with anomalously high query volumes
    This simulates Command and Control or data exfiltration
    """
    events = []
    host = base_host.copy()

    # This host will generate many more queries than normal in a short time frame
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(seconds=random.randint(0, 3600))
        event = generate_normal_dns_event(host, timestamp)
        event["tag"] = "volume_anomaly"
        events.append(event)

    return events


# 2. Beaconing Detection
def generate_beaconing(base_host, start_time, num_events=50, interval_seconds=60):
    """
    Create events at very regular intervals (beaconing)
    This simulates Command and Control communication with an infection
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)

    # Create events at regular intervals with small jitter (typical of C2)
    for i in range(num_events):
        # Add a small jitter (±3 seconds) to the regular interval
        jitter = random.uniform(-3, 3)
        timestamp = start_time + datetime.timedelta(
            seconds=(i * interval_seconds) + jitter
        )

        event = generate_normal_dns_event(host, timestamp)
        event["query"] = generate_subdomain(c2_domain, entropy="high")
        event["tag"] = "beaconing"
        events.append(event)

    return events


# 3. Burst Activity Detection
def generate_burst_activity(base_host, start_time, num_events=100):
    """
    Generate a burst of events in a very short time period
    This simulates sudden malicious activity or data exfiltration
    """
    events = []
    host = base_host.copy()

    # Generate a burst of events in a short time period (5 seconds)
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(seconds=random.uniform(0, 5))
        event = generate_normal_dns_event(host, timestamp)
        event["tag"] = "burst_activity"
        events.append(event)

    return events


# 4. TXT Record Type Anomaly Detection
def generate_txt_record_anomaly(base_host, start_time, num_events=30):
    """
    Generate excessive use of TXT records
    This simulates Command and Control or data exfiltration via DNS
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 120))
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "TXT"
        event["query"] = generate_subdomain(c2_domain, entropy="high")

        # Simulate encoded data in TXT record (base64-like)
        data_length = random.randint(30, 200)
        event["answer"] = "".join(
            random.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
            )
            for _ in range(data_length)
        )
        event["tag"] = "txt_record_anomaly"
        events.append(event)

    return events


# 5. ANY Record Type Anomaly Detection
def generate_any_record_anomaly(base_host, start_time, num_events=20):
    """
    Generate excessive use of ANY records
    This often indicates reconnaissance activity or amplification attacks
    """
    events = []
    host = base_host.copy()

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 120))
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "ANY"
        event["tag"] = "any_record_anomaly"
        events.append(event)

    return events


# 6. Record Type Rarity Analysis
def generate_record_type_rarity(base_host, start_time, num_events=15):
    """
    Generate use of rare record types
    This can indicate unusual/suspicious activity
    """
    events = []
    host = base_host.copy()

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 240))
        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = random.choice(RARE_RECORD_TYPES)
        event["tag"] = "record_type_rarity"
        events.append(event)

    return events


# 7. Query Length Anomaly Detection
def generate_query_length_anomaly(base_host, start_time, num_events=25):
    """
    Generate unusually long DNS queries
    This often indicates data exfiltration via DNS tunneling
    """
    events = []
    host = base_host.copy()
    tunnel_domain = random.choice(MALICIOUS_DOMAINS)

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 180))
        event = generate_normal_dns_event(host, timestamp)

        # Generate an extremely long DNS query (data exfiltration)
        event["query"] = generate_subdomain(tunnel_domain, entropy="extreme")
        event["tag"] = "query_length_anomaly"
        events.append(event)

    return events


# 8. Domain Shadowing Detection
def generate_domain_shadowing(base_host, start_time, num_events=40):
    """
    Generate many unique subdomains for a legitimate domain
    This simulates domain shadowing attacks
    """
    events = []
    host = base_host.copy()
    target_domain = random.choice(TOP_DOMAINS)

    # Generate many unique, random subdomains for the same parent domain
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 240))
        event = generate_normal_dns_event(host, timestamp)

        # Generate a unique random subdomain with high entropy
        event["query"] = generate_subdomain(target_domain, entropy="high")
        event["tag"] = "domain_shadowing"
        events.append(event)

    return events


# 9. Behavioral Clustering
def generate_behavioral_cluster(base_hosts, start_time, cluster_size=5, event_count=30):
    """
    Create a group of hosts with similar abnormal DNS behavior
    This helps demonstrate behavioral clustering for anomaly detection
    """
    all_events = []

    # Select hosts for this cluster
    cluster_hosts = random.sample(base_hosts, min(cluster_size, len(base_hosts)))

    # Define a consistent pattern for this cluster (e.g., similar query types and timing)
    cluster_domain = random.choice(TOP_DOMAINS)
    cluster_record_type = random.choice(list(RECORD_TYPES.keys()))
    query_interval = random.randint(5, 15)  # minutes

    # Give them similar behavior patterns
    for host in cluster_hosts:
        # Cluster behavior: similar query patterns
        for i in range(event_count):
            timestamp = start_time + datetime.timedelta(
                minutes=i * query_interval
                + random.uniform(-1, 1)  # Similar timing with small variance
            )
            event = generate_normal_dns_event(host, timestamp)
            event["query"] = (
                f"api{random.randint(1,5)}.{random.choice(['analytics', 'metrics', 'tracking'])}.{cluster_domain}"
            )
            event["record_type"] = cluster_record_type
            event["tag"] = "behavioral_cluster"
            all_events.append(event)

    return all_events


# 10. High Priority DNS Anomalies Combined
def generate_high_priority_anomalies(base_host, start_time, num_events=35):
    """
    Generate events with multiple anomaly indicators
    This simulates high-confidence malicious activity
    """
    events = []
    host = base_host.copy()
    malicious_domain = random.choice(MALICIOUS_DOMAINS)

    # Generate events with both volume anomalies and query length anomalies
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 180))
        event = generate_normal_dns_event(host, timestamp)

        # Combine multiple anomalous characteristics:
        # 1. Long query (tunneling)
        event["query"] = generate_subdomain(malicious_domain, entropy="extreme")

        # 2. Unusual record type (50% TXT, 50% other unusual type)
        if random.random() < 0.5:
            event["record_type"] = "TXT"
            # Add encoded data
            data_length = random.randint(30, 200)
            event["answer"] = "".join(
                random.choice(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
                )
                for _ in range(data_length)
            )
        else:
            event["record_type"] = random.choice(RARE_RECORD_TYPES)

        event["tag"] = "high_priority_combined"
        events.append(event)

    return events


# 11. DNS C2 Comprehensive Detection
def generate_dns_c2(base_host, start_time, num_events=45):
    """
    Generate a comprehensive C2 pattern combining beaconing and TXT records
    This simulates a full C2 communication channel
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)

    # Combine beaconing behavior with TXT records for a comprehensive C2 pattern
    interval = random.randint(50, 120)  # seconds between beacons

    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            seconds=(i * interval) + random.uniform(-3, 3)  # small jitter
        )
        event = generate_normal_dns_event(host, timestamp)

        # C2 communication often uses TXT records for data transfer
        event["record_type"] = "TXT" if random.random() < 0.7 else "A"
        event["query"] = generate_subdomain(c2_domain, entropy="high")

        if event["record_type"] == "TXT":
            # Simulate encoded commands in TXT record
            cmd_length = random.randint(30, 100)
            event["answer"] = "".join(
                random.choice(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
                )
                for _ in range(cmd_length)
            )

        event["tag"] = "dns_c2"
        events.append(event)

    return events


# 12. DNS Tunneling Comprehensive Detection
def generate_dns_tunneling(base_host, start_time, num_events=50):
    """
    Generate a comprehensive DNS tunneling pattern
    This combines long queries, unusual record types, and high volume
    """
    events = []
    host = base_host.copy()
    tunnel_domain = random.choice(MALICIOUS_DOMAINS)

    # Generate frequent queries with long subdomains (data being sent out)
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            seconds=random.randint(0, 1800)  # Within 30 minutes (high frequency)
        )
        event = generate_normal_dns_event(host, timestamp)

        # 1. High entropy, extremely long subdomain (data being exfiltrated)
        event["query"] = generate_subdomain(tunnel_domain, entropy="extreme")

        # 2. Use of record types that can carry data
        event["record_type"] = random.choices(
            ["TXT", "NULL", "CNAME", "A", "AAAA"],
            weights=[0.4, 0.1, 0.2, 0.2, 0.1],  # Higher weight for TXT
            k=1,
        )[0]

        # 3. For TXT records, include data coming back
        if event["record_type"] == "TXT":
            response_length = random.randint(40, 200)
            event["answer"] = "".join(
                random.choice(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
                )
                for _ in range(response_length)
            )

        event["tag"] = "dns_tunneling"
        events.append(event)

    return events


# Helper function to generate normal baseline activity for all hosts
def generate_baseline_activity(hosts, start_time, end_time):
    """
    Generate baseline normal DNS activity for all hosts for the entire time period
    """
    events = []

    # Calculate the total duration in hours
    duration_hours = int((end_time - start_time).total_seconds() / 3600)

    print(
        f"Generating baseline activity for {len(hosts)} hosts over {duration_hours} hours..."
    )

    # For each host, generate normal queries throughout the time period
    for host in hosts:
        # Determine how many queries this host will make based on its query rate
        # We'll use a Poisson distribution to add some randomness to the query count
        avg_queries_per_hour = host["query_rate"]

        for hour in range(duration_hours):
            # Generate a random number of queries for this hour using the host's query rate
            queries_this_hour = random.randint(
                max(
                    1, int(avg_queries_per_hour * 0.5)
                ),  # At least 1 query, but could be fewer than average
                int(avg_queries_per_hour * 1.5),  # Could be more than average
            )

            # Generate events for this host for this hour
            hour_start = start_time + datetime.timedelta(hours=hour)
            hour_end = hour_start + datetime.timedelta(hours=1)

            for _ in range(queries_this_hour):
                # Random time within this hour
                event_time = hour_start + datetime.timedelta(
                    seconds=random.randint(0, 3599)
                )

                # Create the normal DNS event
                event = generate_normal_dns_event(host, event_time)
                events.append(event)

    return events


def main():
    print(
        f"Generating DNS events over {TIME_PERIOD_DAYS} days following Splunk CIM for Network_Resolution..."
    )

    # Generate the internal hosts
    internal_hosts = generate_internal_hosts(NUM_INTERNAL_HOSTS, LINUX_HOSTS_PERCENTAGE)

    # Set the time range (90 days back from now)
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=TIME_PERIOD_DAYS)

    # Create a list to store all events
    all_events = []

    # Define anomaly types with their generator functions
    anomaly_types = [
        {"name": "Volume Anomaly", "generator": generate_volume_anomaly},
        {"name": "Beaconing", "generator": generate_beaconing},
        {"name": "Burst Activity", "generator": generate_burst_activity},
        {"name": "TXT Record Anomaly", "generator": generate_txt_record_anomaly},
        {"name": "ANY Record Anomaly", "generator": generate_any_record_anomaly},
        {"name": "Record Type Rarity", "generator": generate_record_type_rarity},
        {"name": "Query Length Anomaly", "generator": generate_query_length_anomaly},
        {"name": "Domain Shadowing", "generator": generate_domain_shadowing},
        {
            "name": "High Priority Combined",
            "generator": generate_high_priority_anomalies,
        },
        {"name": "DNS C2", "generator": generate_dns_c2},
        {"name": "DNS Tunneling", "generator": generate_dns_tunneling},
    ]

    # We need to handle behavioral clustering separately since it involves multiple hosts
    behavioral_clustering = {
        "name": "Behavioral Cluster",
        "generator": generate_behavioral_cluster,
    }

    # Randomly select 11 hosts for individual anomalies
    random.shuffle(internal_hosts)
    anomalous_hosts = internal_hosts[:11]
    normal_hosts = internal_hosts[11:]

    # Keep track of which host gets which anomaly
    host_anomaly_map = {}

    print("Generating baseline normal DNS activity for all hosts...")
    # Generate baseline normal activity for all hosts (including the anomalous ones)
    baseline_events = generate_baseline_activity(internal_hosts, start_time, end_time)
    all_events.extend(baseline_events)
    print(f"Generated {len(baseline_events)} baseline events.")

    # Assign 11 anomaly types to individual hosts
    for i, anomaly_type in enumerate(anomaly_types):
        if i >= len(anomalous_hosts):
            break

        host = anomalous_hosts[i]
        host_anomaly_map[host["hostname"]] = anomaly_type["name"]

        # Generate a random time for this anomaly
        random_day = random.randint(0, TIME_PERIOD_DAYS - 1)
        anomaly_time = start_time + datetime.timedelta(
            days=random_day, hours=random.randint(0, 23), minutes=random.randint(0, 59)
        )

        # Generate the anomaly events
        anomaly_events = anomaly_type["generator"](host, anomaly_time)
        all_events.extend(anomaly_events)
        print(
            f"Generated {len(anomaly_events)} events for {anomaly_type['name']} on host {host['hostname']}"
        )

    # Handle behavioral clustering separately (needs multiple hosts)
    # Select 5 random hosts from the normal hosts for the behavioral cluster
    cluster_size = min(5, len(normal_hosts))
    cluster_hosts = normal_hosts[:cluster_size]

    # Record these hosts as part of the behavioral cluster
    for host in cluster_hosts:
        host_anomaly_map[host["hostname"]] = behavioral_clustering["name"]

    # Generate a random time for behavioral clustering
    random_day = random.randint(0, TIME_PERIOD_DAYS - 1)
    anomaly_time = start_time + datetime.timedelta(
        days=random_day, hours=random.randint(0, 23), minutes=random.randint(0, 59)
    )

    # Generate the behavioral clustering events
    cluster_events = behavioral_clustering["generator"](
        cluster_hosts,
        anomaly_time,
        cluster_size=cluster_size,
        event_count=random.randint(20, 40),
    )
    all_events.extend(cluster_events)
    print(
        f"Generated {len(cluster_events)} events for Behavioral Cluster across {cluster_size} hosts"
    )

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
        f.write(
            f"Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # Count events by tag
        tag_counts = defaultdict(int)
        for event in all_events:
            if "tag" in event:
                tag_counts[event["tag"]] += 1
            else:
                tag_counts["normal"] += 1

        f.write("Event counts by type:\n")
        for tag, count in sorted(tag_counts.items()):
            if tag == "normal":
                f.write(f"- Normal DNS events: {count}\n")
            else:
                f.write(f"- {tag}: {count} events\n")

        f.write("\nAnomalous hosts (one per anomaly type):\n")
        for hostname, anomaly_name in host_anomaly_map.items():
            host_info = next(
                (h for h in internal_hosts if h["hostname"] == hostname), None
            )
            if host_info:
                f.write(f"{anomaly_name}: {host_info['ip']} ({hostname})\n")

        f.write("\nDetection Methods (based on academic research):\n")
        f.write(
            "1. Volume/Frequency Anomalies: Use DensityFunction on query count by src\n"
        )
        f.write(
            "2. Beaconing: Calculate gaps between queries and check for low standard deviation\n"
        )
        f.write(
            "3. Burst Activity: Use streamstats time_window to detect sudden spikes\n"
        )
        f.write(
            "4. TXT Record Anomalies: Monitor for abnormal usage of TXT records by src\n"
        )
        f.write(
            "5. ANY Record Anomalies: Look for hosts using ANY queries (often used in recon)\n"
        )
        f.write(
            "6. Record Type Rarity: Find hosts using statistically rare record types\n"
        )
        f.write(
            "7. Query Length Anomalies: Calculate query length and use DensityFunction to find outliers\n"
        )
        f.write(
            "8. Domain Shadowing: Count unique subdomains per parent domain and look for anomalies\n"
        )
        f.write(
            "9. Behavioral Clustering: Apply KMeans clustering to multiple DNS behavior metrics\n"
        )
        f.write(
            "10. High Priority Combined: Correlate multiple anomaly indicators for high confidence\n"
        )
        f.write(
            "11. DNS C2: Look for beaconing combined with data exchange through DNS\n"
        )
        f.write(
            "12. DNS Tunneling: Identify excessively long queries, high volume, and data transfer\n"
        )

    print(f"Generated {len(all_events)} DNS events and saved to {OUTPUT_FILE}")
    print(f"Summary saved to dns_events_summary.txt")


if __name__ == "__main__":
    main()
