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
MAX_EVENTS = 500000  # Maximum number of events to generate
OUTPUT_FILE = "dns_events.json"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
TIME_PERIOD_DAYS = 30  # 1 month of data

# Organization infrastructure simulation
NUM_INTERNAL_HOSTS = 100  # Realistic number of hosts in a medium-sized organization
LINUX_HOSTS_PERCENTAGE = 20  # 20% of hosts are Linux servers
TOTAL_ANOMALIES = 10  # We'll ensure all anomaly types are represented
ANOMALY_HOSTS = 10  # Exactly 10 hosts will have anomalies

# Common English/American names for realistic host naming
COMMON_NAMES = [
    "john",
    "david",
    "michael",
    "james",
    "robert",
    "william",
    "joseph",
    "thomas",
    "charles",
    "mary",
    "patricia",
    "jennifer",
    "linda",
    "elizabeth",
    "barbara",
    "susan",
    "jessica",
    "sarah",
    "karen",
    "lisa",
    "nancy",
    "betty",
    "margaret",
    "sandra",
    "ashley",
    "kimberly",
    "emily",
    "donna",
    "michelle",
    "carol",
    "amanda",
    "melissa",
    "deborah",
    "stephanie",
    "rebecca",
    "laura",
    "helen",
    "sharon",
    "cynthia",
    "kathleen",
    "amy",
    "shirley",
    "anna",
    "angela",
    "ruth",
    "brenda",
    "pamela",
    "nicole",
    "katherine",
    "samantha",
    "christine",
    "emma",
    "catherine",
    "debra",
    "virginia",
    "rachel",
    "carolyn",
    "janet",
    "maria",
    "heather",
    "diane",
    "julie",
    "joyce",
    "victoria",
    "kelly",
    "christina",
    "lauren",
    "joan",
    "evelyn",
    "olivia",
    "judith",
    "megan",
    "cheryl",
    "martha",
    "andrea",
    "frances",
    "hannah",
    "jacqueline",
    "ann",
    "gloria",
    "jean",
    "kathryn",
    "alice",
    "teresa",
    "sara",
    "janice",
    "doris",
    "madison",
    "julia",
    "grace",
    "judy",
    "abigail",
    "marie",
    "denise",
    "beverly",
    "amber",
    "theresa",
    "marilyn",
    "danielle",
    "diana",
    "brittany",
    "natalie",
    "sophia",
    "rose",
    "isabella",
    "richard",
    "daniel",
    "paul",
    "mark",
    "donald",
    "george",
    "kenneth",
    "steven",
    "edward",
    "brian",
    "ronald",
    "anthony",
    "kevin",
    "jason",
    "matthew",
    "gary",
    "timothy",
    "jose",
    "larry",
    "jeffrey",
    "frank",
    "scott",
    "eric",
    "stephen",
    "andrew",
    "raymond",
    "gregory",
    "joshua",
    "jerry",
    "dennis",
    "walter",
    "patrick",
    "peter",
    "harold",
    "douglas",
    "henry",
    "carl",
    "arthur",
    "ryan",
    "roger",
    "joe",
    "juan",
    "jack",
    "albert",
    "jonathan",
    "justin",
    "terry",
    "gerald",
    "keith",
    "samuel",
    "willie",
    "ralph",
    "lawrence",
    "nicholas",
    "roy",
    "benjamin",
    "bruce",
    "brandon",
    "adam",
    "harry",
    "fred",
    "wayne",
    "billy",
    "steve",
    "louis",
    "jeremy",
    "aaron",
    "randy",
    "howard",
    "eugene",
    "carlos",
    "russell",
    "bobby",
    "victor",
    "martin",
    "ernest",
    "phillip",
    "todd",
    "jesse",
    "craig",
    "alan",
    "shawn",
    "clarence",
    "sean",
    "philip",
    "chris",
    "johnny",
    "earl",
    "jimmy",
    "antonio",
    "danny",
    "bryan",
    "tony",
    "luis",
    "mike",
    "stanley",
    "leonard",
    "nathan",
    "dale",
    "manuel",
    "rodney",
    "curtis",
    "norman",
    "allen",
    "marvin",
    "vincent",
    "glenn",
    "jeffery",
    "travis",
    "jeff",
    "chad",
    "jacob",
    "lee",
    "melvin",
    "alfred",
    "kyle",
    "francis",
    "bradley",
    "jesus",
    "herbert",
    "frederick",
    "ray",
    "joel",
    "edwin",
    "don",
    "eddie",
    "ricky",
    "troy",
    "randall",
    "barry",
    "alexander",
    "bernard",
    "mario",
    "leroy",
    "francisco",
    "marcus",
    "micheal",
    "theodore",
    "clifford",
    "miguel",
    "oscar",
    "jay",
    "jim",
    "tom",
    "calvin",
    "alex",
    "jon",
    "ronnie",
    "bill",
    "lloyd",
    "tommy",
    "leon",
    "derek",
    "warren",
    "darrell",
    "jerome",
    "floyd",
    "leo",
    "alvin",
    "tim",
    "wesley",
    "gordon",
    "dean",
    "greg",
    "jorge",
    "dustin",
    "pedro",
    "derrick",
    "dan",
    "lewis",
    "zachary",
    "corey",
    "herman",
    "maurice",
    "vernon",
    "roberto",
    "clyde",
    "glen",
    "hector",
    "shane",
    "ricardo",
    "sam",
    "rick",
    "lester",
    "brent",
    "ramon",
    "charlie",
    "tyler",
    "gilbert",
    "gene",
    "marc",
    "reginald",
    "ruben",
    "brett",
    "angel",
    "nathaniel",
    "rafael",
    "leslie",
    "edgar",
    "milton",
    "raul",
    "ben",
    "chester",
    "cecil",
    "duane",
    "franklin",
    "andre",
    "elmer",
    "brad",
    "gabriel",
    "ron",
    "mitchell",
    "roland",
    "arnold",
    "harvey",
    "jared",
    "adrian",
    "karl",
    "cory",
    "claude",
    "erik",
    "darryl",
    "jamie",
    "neil",
    "jessie",
    "christian",
    "javier",
    "fernando",
    "clinton",
    "ted",
    "mathew",
    "tyrone",
    "darren",
    "lonnie",
    "lance",
    "cody",
    "julio",
    "kelly",
    "kurt",
    "allan",
    "nelson",
    "guy",
    "clayton",
    "hugh",
    "max",
    "dwayne",
    "dwight",
    "armando",
    "felix",
    "jimmie",
    "everett",
    "jordan",
    "ian",
    "wallace",
    "ken",
    "bob",
    "jaime",
    "casey",
    "alfredo",
    "alberto",
    "dave",
    "ivan",
    "johnnie",
    "sidney",
    "byron",
    "julian",
    "isaac",
    "morris",
    "clifton",
    "willard",
    "daryl",
    "ross",
    "virgil",
    "andy",
    "marshall",
    "salvador",
    "perry",
    "kirk",
    "sergio",
    "marion",
    "tracy",
    "seth",
    "kent",
    "terrance",
    "rene",
    "eduardo",
    "terrence",
    "enrique",
    "freddie",
    "wade",
]

# Windows OS versions for realistic host naming
WINDOWS_OS_VERSIONS = [
    "win10",
    "win11",
    "win7",
    "winxp",
    "win2k19",
    "win2k16",
    "win2k12",
]

# Linux distributions for realistic host naming
LINUX_DISTRIBUTIONS = [
    "ubuntu",
    "fedora",
    "debian",
    "centos",
    "rhel",
    "suse",
    "arch",
    "kali",
]

# Device types for realistic host naming
DEVICE_TYPES = ["laptop", "desktop", "wks", "pc", "tablet", "server", "vm"]

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

# More pronounced record type distribution to make anomalies clearly stand out
RECORD_TYPES = {
    "A": 80,  # 80% for normal traffic
    "AAAA": 15,  # 15% probability
    "MX": 2,  # Reduced to make TXT and ANY anomalies more visible
    "TXT": 0.5,  # Very low default TXT usage
    "CNAME": 2,  # Reduced to emphasize A records more
    "NS": 0.3,  # Less common
    "PTR": 0.2,  # Less common
    "ANY": 0.01,  # Extremely rare in normal traffic
}

# Rare record types for anomaly generation
RARE_RECORD_TYPES = ["SPF", "SRV", "DNSKEY", "NSEC", "NSEC3", "HINFO", "AXFR"]

REPLY_CODES = {
    "NOERROR": 0.975,  # 97.5% successful queries
    "NXDOMAIN": 0.02,  # 2% domain not found
    "SERVFAIL": 0.004,  # 0.4% server failure
    "REFUSED": 0.001,  # 0.1% query refused
}

# Departmental segmentation for more realistic network simulation
DEPARTMENTS = [
    {
        "name": "IT",
        "subnet": "10.1.1.0/24",
        "host_count": 15,
        "query_rate_range": (10, 50),  # More realistic query rates
    },
    {
        "name": "Engineering",
        "subnet": "10.1.2.0/24",
        "host_count": 25,
        "query_rate_range": (8, 40),  # More realistic query rates
    },
    {
        "name": "Sales",
        "subnet": "10.1.3.0/24",
        "host_count": 20,
        "query_rate_range": (5, 25),  # More realistic query rates
    },
    {
        "name": "Marketing",
        "subnet": "10.1.4.0/24",
        "host_count": 15,
        "query_rate_range": (5, 25),  # More realistic query rates
    },
    {
        "name": "Finance",
        "subnet": "10.1.5.0/24",
        "host_count": 10,
        "query_rate_range": (3, 15),  # More realistic query rates
    },
    {
        "name": "HR",
        "subnet": "10.1.6.0/24",
        "host_count": 5,
        "query_rate_range": (2, 10),  # More realistic query rates
    },
    {
        "name": "Servers",
        "subnet": "10.2.0.0/24",
        "host_count": 10,
        "query_rate_range": (20, 80),  # More realistic query rates for servers
    },
]

# Define workday patterns for realistic activity cycles
WORKDAY_HOURS = {
    0: 0.1,  # 12am: 10% of normal activity (maintenance, etc)
    1: 0.05,  # 1am: 5% of normal activity
    2: 0.05,  # 2am: 5% of normal activity
    3: 0.05,  # 3am: 5% of normal activity
    4: 0.1,  # 4am: 10% of normal activity
    5: 0.2,  # 5am: 20% of normal activity
    6: 0.3,  # 6am: 30% of normal activity
    7: 0.6,  # 7am: 60% of normal activity
    8: 0.9,  # 8am: 90% of normal activity
    9: 1.0,  # 9am: 100% of normal activity (peak)
    10: 1.0,  # 10am: 100% of normal activity
    11: 1.0,  # 11am: 100% of normal activity
    12: 0.8,  # 12pm: 80% of normal activity (lunch)
    13: 0.9,  # 1pm: 90% of normal activity
    14: 1.0,  # 2pm: 100% of normal activity
    15: 1.0,  # 3pm: 100% of normal activity
    16: 1.0,  # 4pm: 100% of normal activity
    17: 0.8,  # 5pm: 80% of normal activity
    18: 0.5,  # 6pm: 50% of normal activity
    19: 0.3,  # 7pm: 30% of normal activity
    20: 0.2,  # 8pm: 20% of normal activity
    21: 0.2,  # 9pm: 20% of normal activity
    22: 0.15,  # 10pm: 15% of normal activity
    23: 0.1,  # 11pm: 10% of normal activity
}

WEEKEND_HOURS = {hour: rate * 0.3 for hour, rate in WORKDAY_HOURS.items()}

# Anomaly types that match the detection methods in Splunk with comments
# aligned with the macro definitions in macros.conf
ANOMALY_TYPES = [
    "C2_TUNNELING",  # dns_c2_tunneling_detection - High volume of DNS queries
    "BEACONING",  # dns_beaconing_detection - Regular, periodic queries with consistent gaps
    "TXT_RECORD_ANOMALY",  # dns_txt_record_detection - Unusual use of TXT records for C&C or data exfil
    "ANY_RECORD_ANOMALY",  # dns_any_record_detection - Reconnaissance using ANY queries
    "HINFO_RECORD_ANOMALY",  # dns_hinfo_record_detection - Reconnaissance using HINFO queries
    "AXFR_RECORD_ANOMALY",  # dns_axfr_record_detection - Zone transfer attempts
    "QUERY_LENGTH_ANOMALY",  # dns_query_length_detection - Unusually long queries for data exfil
    "DOMAIN_SHADOWING",  # dns_domain_shadowing_detection - Many unique subdomains for same parent
    "BEHAVIORAL_CLUSTER",  # dns_behavioral_clustering_detection - Similar patterns across multiple hosts
]

# Anomaly configuration to align with Splunk detection thresholds
ANOMALY_CONFIG = {
    "C2_TUNNELING": {
        "num_events": 5000,  # Significantly increased to ensure detection
        "time_window_hours": 1,  # Concentrated in 1-hour windows to trigger hourly detection
        "description": "High volume DNS queries from single host within short time period",
    },
    "BEACONING": {
        "interval_minutes": 5,  # More frequent beaconing
        "num_events": 2000,  # Significantly increased to ensure detection
        "jitter_seconds": 2,  # Even smaller jitter for more obvious pattern
        "description": "Periodic DNS queries at regular intervals with minimal time variation",
    },
    "TXT_RECORD_ANOMALY": {
        "num_events": 1000,  # Significantly increased to ensure detection
        "min_content_length": 100,  # Longer TXT records
        "max_content_length": 300,  # Longer max content
        "description": "Unusual volume of TXT record queries with encoded content",
    },
    "ANY_RECORD_ANOMALY": {
        "num_events": 800,  # Significantly increased to ensure detection
        "description": "Unusual volume of ANY record queries indicating potential reconnaissance",
    },
    "HINFO_RECORD_ANOMALY": {
        "num_events": 600,  # Significantly increased to ensure detection
        "description": "Unusual HINFO record queries for system information gathering",
    },
    "AXFR_RECORD_ANOMALY": {
        "num_events": 500,  # Significantly increased to ensure detection
        "description": "Zone transfer attempts using AXFR queries",
    },
    "QUERY_LENGTH_ANOMALY": {
        "num_events": 1500,  # Significantly increased to ensure detection
        "min_length": 200,  # Even longer queries
        "description": "Abnormally long DNS query strings indicating potential data exfiltration",
    },
    "DOMAIN_SHADOWING": {
        "num_events": 2000,  # Significantly increased to ensure detection
        "unique_subdomains": 500,  # Significantly increased unique subdomains
        "description": "Excessive unique subdomains for a single parent domain",
    },
    "BEHAVIORAL_CLUSTER": {
        "cluster_size": 3,  # Number of hosts with same behavior
        "events_per_host": 1000,  # Significantly increased events per host
        "description": "Multiple hosts exhibiting synchronized suspicious DNS behavior",
    },
}


# Generate internal hosts based on departmental structure with realistic names
def generate_internal_hosts():
    hosts = []

    # Generate hosts for each department
    for dept in DEPARTMENTS:
        subnet = ipaddress.ip_network(dept["subnet"])
        ip_list = list(subnet.hosts())

        for i in range(min(dept["host_count"], len(ip_list))):
            ip = str(ip_list[i])

            # Select a random name from the common names list
            name = random.choice(COMMON_NAMES)

            # Determine OS type
            if dept["name"] == "Servers":
                os_type = (
                    "linux" if random.random() < 0.8 else "windows"
                )  # 80% Linux servers

                if os_type == "linux":
                    linux_dist = random.choice(LINUX_DISTRIBUTIONS)
                    hostname_prefix = (
                        f"{random.choice(['srv', 'app', 'db', 'web', 'api'])}"
                    )
                    hostname = f"{hostname_prefix}-{random.randint(100, 999)}.internal"
                else:
                    win_version = random.choice(WINDOWS_OS_VERSIONS)
                    hostname_prefix = (
                        f"{random.choice(['srv', 'app', 'db', 'web', 'api'])}"
                    )
                    hostname = f"{hostname_prefix}-{random.randint(100, 999)}.internal"
            else:
                # Non-server hosts get personal names
                os_type = (
                    "linux"
                    if random.random() < (LINUX_HOSTS_PERCENTAGE / 100)
                    else "windows"
                )

                if os_type == "windows":
                    win_version = random.choice(WINDOWS_OS_VERSIONS)
                    device_type = random.choice(DEVICE_TYPES)

                    # Format: john-win10, mike-laptop, etc.
                    if random.random() < 0.5:  # 50% chance to include department
                        hostname = f"{name}-{win_version}-{dept['name'].lower()}"
                    else:
                        hostname = f"{name}-{win_version}"
                else:
                    linux_dist = random.choice(LINUX_DISTRIBUTIONS)
                    device_type = random.choice(DEVICE_TYPES)

                    # Format: susan-ubuntu, hr-laptop-alex, etc.
                    if random.random() < 0.3:  # 30% chance to have department prefix
                        hostname = f"{dept['name'].lower()}-{device_type}-{name}"
                    else:
                        hostname = f"{name}-{linux_dist}"

            # Add individual variance to query rates (some users are heavier than others)
            min_rate, max_rate = dept["query_rate_range"]
            base_query_rate = random.randint(min_rate, max_rate)

            # Add up to ±30% individual variance
            individual_multiplier = random.uniform(0.7, 1.3)
            query_rate = int(base_query_rate * individual_multiplier)

            # Ensure minimum query rate
            query_rate = max(1, query_rate)

            hosts.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "os": os_type,
                    "department": dept["name"],
                    "query_rate": query_rate,
                    "user_name": name,  # Store the user name for reference
                }
            )

    return hosts


# Generate subdomains for a given domain
def generate_subdomain(domain, length=None, entropy="normal"):
    if length is None:
        if entropy == "normal":
            length = random.randint(1, 2)  # Normal subdomains are relatively short
        elif entropy == "high":
            length = random.randint(
                3, 6
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
                "auth",
                "login",
                "secure",
                "shop",
                "store",
                "blog",
                "docs",
            ]
            if (
                random.random() < 0.8 and part_options
            ):  # 80% chance of using common subdomain
                part = random.choice(part_options)
            else:
                part_length = random.randint(3, 6)
                part = "".join(
                    random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                    for _ in range(part_length)
                )
        elif entropy == "high":
            # High entropy subdomains have more randomness
            part_length = random.randint(10, 15)
            part = "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                for _ in range(part_length)
            )
        elif entropy == "extreme":
            # Extreme entropy subdomains for data exfiltration
            part_length = random.randint(40, 60)
            part = "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                for _ in range(part_length)
            )

        subdomain_parts.append(part)

    return ".".join(subdomain_parts) + "." + domain


# Generate normal DNS event with more realistic patterns
def generate_normal_dns_event(host, timestamp):
    # Select domain based on a realistic distribution (frequent sites more common)
    domain_weights = [
        100,
        90,
        85,
        80,
        75,
        70,
        65,
        60,
        55,
        50,
        45,
        40,
        35,
        30,
        25,
        20,
        15,
        10,
        5,
        5,
        5,
        5,
        5,
        5,
    ]
    domain = random.choices(
        TOP_DOMAINS[: len(domain_weights)],
        weights=domain_weights[: len(TOP_DOMAINS)],
        k=1,
    )[0]

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

    # Determine the application that generated the DNS query
    if host["department"] == "Servers":
        app = random.choices(
            [
                "system_service",
                "dns_service",
                "web_service",
                "database",
                "scheduled_task",
            ],
            weights=[60, 15, 10, 10, 5],
            k=1,
        )[0]
    else:
        app = random.choices(
            [
                "browser",
                "email_client",
                "os_update",
                "antivirus",
                "office_app",
                "chat_app",
            ],
            weights=[70, 10, 8, 5, 5, 2],
            k=1,
        )[0]

    # Determine action based on reply code (CIM compliance)
    if reply_code == "NOERROR":
        action = "resolved"
    else:
        action = "queried"

    # Generate response time (previously called duration)
    response_time = random.uniform(0.001, 0.05)  # Query response time in seconds

    # Generate DNS event following Splunk's CIM for Network Resolution
    event = {
        "timestamp": timestamp.strftime(TIMESTAMP_FORMAT),
        "source": "dns",
        "sourcetype": "dns",
        "host": host["hostname"],
        "eventtype": "dns",  # CIM compliance
        # CIM fields for DNS
        "src": host["ip"],
        "src_host": host["hostname"],
        "dest_port": 53,
        "dest": dns_server,  # Internal DNS server
        "record_type": record_type,
        "query_type": record_type,  # CIM field - copy of record_type
        "query": query,
        "answer": answer,
        "message_type": "QUERY",
        "reply_code": reply_code,
        "action": action,  # CIM field - resolved or queried
        "app": app,  # CIM field - application that generated the query
        "user": f"user_{host['department'].lower()}_{random.randint(1, 50)}",  # Department-based user
        "response_time": response_time,  # CIM field (renamed from duration)
        "transport": "UDP" if random.random() < 0.95 else "TCP",
        "vendor_product": "Microsoft DNS" if host["os"] == "windows" else "BIND",
        "department": host["department"],  # Adding department info for analysis
        # Extract parent domain and subdomain for Splunk analysis
        "parent_domain": (
            query.split(".")[-2] + "." + query.split(".")[-1]
            if len(query.split(".")) > 1
            else query
        ),
        "subdomain": (
            ".".join(query.split(".")[:-2]) if len(query.split(".")) > 2 else ""
        ),
    }

    return event


# Anomaly generation functions - updated to match Splunk detection methods


# 1. C2 Tunneling - High volume of DNS queries
def generate_c2_tunneling(base_host, start_time):
    """
    Generate events with anomalously high query volumes
    This simulates Command and Control or data exfiltration
    Designed to trigger: dns_c2_tunneling_detection in Splunk
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)
    config = ANOMALY_CONFIG["C2_TUNNELING"]

    # Generate high concentration of events in 1-hour window to trigger hourly detection
    time_window_hours = config["time_window_hours"]
    num_events = config["num_events"]

    # Generate hourly timestamps to spread the events within the window
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.uniform(0, time_window_hours),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)

        # C2 traffic has distinct patterns - highly random subdomains
        event["query"] = generate_subdomain(c2_domain, entropy="high")

        # Most C2 uses A records, sometimes AAAA and TXT
        event["record_type"] = random.choices(
            ["A", "AAAA", "TXT"], weights=[70, 15, 15], k=1
        )[0]

        # Add anomaly type and metadata
        event["anomaly_type"] = "C2_TUNNELING"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 2. Beaconing Detection - Regular, periodic DNS queries
def generate_beaconing(base_host, start_time):
    """
    Create events at very regular intervals (beaconing)
    This simulates Command and Control communication with an infection
    Designed to trigger: dns_beaconing_detection in Splunk
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)
    config = ANOMALY_CONFIG["BEACONING"]

    interval_minutes = config["interval_minutes"]
    num_events = config["num_events"]
    jitter_seconds = config["jitter_seconds"]

    # Use the same parent domain for all queries to establish a pattern
    # Create events at regular intervals with minimal jitter
    for i in range(num_events):
        # Add minimal jitter to the regular interval
        jitter = random.uniform(-jitter_seconds, jitter_seconds)
        timestamp = start_time + datetime.timedelta(
            minutes=(i * interval_minutes), seconds=jitter
        )

        event = generate_normal_dns_event(host, timestamp)

        # Use a consistent domain pattern with slight variations in subdomain
        subdomain = f"beacon-{i:04d}"
        event["query"] = f"{subdomain}.{c2_domain}"

        # Most beaconing uses A records
        event["record_type"] = "A" if random.random() < 0.95 else "TXT"

        # Add consistent IP answers to establish pattern
        if event["record_type"] == "A" and event["reply_code"] == "NOERROR":
            # C2 servers often have specific IP ranges
            event["answer"] = f"93.184.{random.randint(1, 5)}.{random.randint(1, 254)}"

        # Add anomaly type and metadata
        event["anomaly_type"] = "BEACONING"
        event["anomaly_description"] = config["description"]
        event["gap"] = interval_minutes * 60 + jitter  # For analysis
        events.append(event)

    return events


# 3. TXT Record Anomaly Detection - Unusual use of TXT records
def generate_txt_record_anomaly(base_host, start_time):
    """
    Generate excessive use of TXT records
    This simulates Command and Control or data exfiltration via DNS
    Designed to trigger: dns_txt_record_detection in Splunk
    """
    events = []
    host = base_host.copy()
    c2_domain = random.choice(MALICIOUS_DOMAINS)
    config = ANOMALY_CONFIG["TXT_RECORD_ANOMALY"]

    num_events = config["num_events"]
    min_content_length = config["min_content_length"]
    max_content_length = config["max_content_length"]

    # Generate many TXT record queries from the same host
    for i in range(num_events):
        # Spread over a few hours to ensure hourly counts are high
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 3),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "TXT"

        # Create unique subdomain for each query
        event["query"] = generate_subdomain(c2_domain, entropy="high")

        # Simulate encoded data in TXT record (base64-like)
        data_length = random.randint(min_content_length, max_content_length)
        # Create suspicious-looking base64 data with command patterns
        prefixes = ["cmd=", "exec=", "run=", "data=", ""]
        prefix = random.choice(prefixes)

        encoded_data = "".join(
            random.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
            )
            for _ in range(data_length - len(prefix))
        )

        event["answer"] = f'"{prefix}{encoded_data}"'
        event["txt_content"] = f"{prefix}{encoded_data}"  # For Splunk analysis

        # Add anomaly type and metadata
        event["anomaly_type"] = "TXT_RECORD_ANOMALY"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 4. ANY Record Anomaly Detection - Reconnaissance using ANY queries
def generate_any_record_anomaly(base_host, start_time):
    """
    Generate excessive use of ANY records
    This often indicates reconnaissance activity or amplification attacks
    Designed to trigger: dns_any_record_detection in Splunk
    """
    events = []
    host = base_host.copy()
    config = ANOMALY_CONFIG["ANY_RECORD_ANOMALY"]
    num_events = config["num_events"]

    # Create a sequence of ANY queries for reconnaissance
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 4),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "ANY"

        # ANY queries often target major organizations for recon
        domains_of_interest = random.sample(TOP_DOMAINS, min(8, len(TOP_DOMAINS)))
        event["query"] = random.choice(domains_of_interest)

        # Add anomaly type and metadata
        event["anomaly_type"] = "ANY_RECORD_ANOMALY"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 5. HINFO Record Anomaly Detection - Reconnaissance using HINFO queries
def generate_hinfo_record_anomaly(base_host, start_time):
    """
    Generate use of HINFO record types for reconnaissance
    This can indicate attempts to gather system information
    Designed to trigger: dns_hinfo_record_detection in Splunk
    """
    events = []
    host = base_host.copy()
    config = ANOMALY_CONFIG["HINFO_RECORD_ANOMALY"]
    num_events = config["num_events"]

    # HINFO queries are very rare, so this is clearly anomalous behavior
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 3),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "HINFO"

        # Targeting various high-value targets for host information gathering
        high_value_targets = [
            "mail",
            "vpn",
            "remote",
            "admin",
            "internal",
            "db",
            "auth",
        ]
        target = random.choice(high_value_targets)
        org = random.choice(TOP_DOMAINS)
        event["query"] = f"{target}.{org}"

        # Add anomaly type and metadata
        event["anomaly_type"] = "HINFO_RECORD_ANOMALY"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 6. AXFR Record Anomaly Detection - Reconnaissance using AXFR queries
def generate_axfr_record_anomaly(base_host, start_time):
    """
    Generate use of AXFR record types for zone transfer attempts
    This can indicate reconnaissance or information gathering
    Designed to trigger: dns_axfr_record_detection in Splunk
    """
    events = []
    host = base_host.copy()
    config = ANOMALY_CONFIG["AXFR_RECORD_ANOMALY"]
    num_events = config["num_events"]

    # AXFR queries are extremely rare in normal traffic
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 2),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)
        event["record_type"] = "AXFR"

        # Typically targeting authoritative name servers
        target_domains = random.sample(TOP_DOMAINS, min(5, len(TOP_DOMAINS)))
        domain = random.choice(target_domains)
        event["query"] = f"ns1.{domain}"

        # Zone transfers are typically rejected
        event["reply_code"] = "REFUSED" if random.random() < 0.95 else "NOERROR"

        # Use TCP for AXFR queries
        event["transport"] = "TCP"

        # Add anomaly type and metadata
        event["anomaly_type"] = "AXFR_RECORD_ANOMALY"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 7. Query Length Anomaly Detection - Unusually long DNS queries
def generate_query_length_anomaly(base_host, start_time):
    """
    Generate unusually long DNS queries
    This often indicates data exfiltration via DNS tunneling
    Designed to trigger: dns_query_length_detection in Splunk
    """
    events = []
    host = base_host.copy()
    tunnel_domain = random.choice(MALICIOUS_DOMAINS)
    config = ANOMALY_CONFIG["QUERY_LENGTH_ANOMALY"]

    num_events = config["num_events"]
    min_length = config["min_length"]

    # Generate abnormally long queries for data exfil
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 5),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)

        # Generate an extremely long DNS query simulating encoded data
        # This will create subdomains over 100 chars
        event["query"] = generate_subdomain(tunnel_domain, entropy="extreme")

        # Make sure query is long enough to trigger detection
        while len(event["query"]) < min_length:
            event["query"] = generate_subdomain(tunnel_domain, entropy="extreme")

        # Query length anomalies often use A records to blend in
        event["record_type"] = "A" if random.random() < 0.8 else "TXT"

        # Add query length explicitly for analysis
        event["query_length"] = len(event["query"])

        # Add anomaly type and metadata
        event["anomaly_type"] = "QUERY_LENGTH_ANOMALY"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 8. Domain Shadowing Detection - Many unique subdomains
def generate_domain_shadowing(base_host, start_time):
    """
    Generate many unique subdomains for a legitimate domain
    This simulates domain shadowing attacks
    Designed to trigger: dns_domain_shadowing_detection in Splunk
    """
    events = []
    host = base_host.copy()
    config = ANOMALY_CONFIG["DOMAIN_SHADOWING"]

    # Use a single legitimate top domain to shadow
    target_domain = random.choice(TOP_DOMAINS[:10])  # Choose from top popular domains
    num_events = config["num_events"]
    unique_subdomains = config["unique_subdomains"]

    # Generate a large number of highly unique subdomains for same parent domain
    for i in range(num_events):
        timestamp = start_time + datetime.timedelta(
            hours=random.randint(0, 8),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        event = generate_normal_dns_event(host, timestamp)

        # Create unique random subdomain with high entropy for each query
        subdomain_id = i % unique_subdomains
        subdomain = f"x{subdomain_id}-" + "".join(
            random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(random.randint(8, 15))
        )
        event["query"] = f"{subdomain}.{target_domain}"
        event["parent_domain"] = target_domain
        event["subdomain"] = subdomain

        # Usually A records pointing to malicious IPs
        event["record_type"] = "A"

        # Shadow domains often resolve to suspicious IPs
        if event["reply_code"] == "NOERROR":
            # Generate suspicious-looking IPs
            suspicious_ranges = ["185.220.", "45.95.", "91.219.", "103.15."]
            suspicious_prefix = random.choice(suspicious_ranges)
            event["answer"] = (
                f"{suspicious_prefix}{random.randint(0, 255)}.{random.randint(1, 255)}"
            )

        # Add anomaly type and metadata
        event["anomaly_type"] = "DOMAIN_SHADOWING"
        event["anomaly_description"] = config["description"]
        events.append(event)

    return events


# 9. Behavioral Clustering - Similar abnormal DNS behavior across hosts
def generate_behavioral_cluster(base_hosts, start_time):
    """
    Create a group of hosts with similar abnormal DNS behavior
    This helps demonstrate behavioral clustering for anomaly detection
    Designed to trigger: dns_behavioral_clustering_detection in Splunk
    """
    all_events = []
    config = ANOMALY_CONFIG["BEHAVIORAL_CLUSTER"]
    cluster_size = min(config["cluster_size"], len(base_hosts))

    # Select hosts for this cluster
    cluster_hosts = random.sample(base_hosts, cluster_size)

    # Define a consistent pattern for this botnet-like activity
    cluster_domain = random.choice(MALICIOUS_DOMAINS)
    cluster_record_type = random.choice(["A", "TXT"])
    query_interval = random.randint(15, 25)  # minutes
    events_per_host = config["events_per_host"]

    # Create consistent beacon-like pattern across multiple hosts
    for host in cluster_hosts:
        for i in range(events_per_host):
            # Similar timing with slight variations
            timestamp = start_time + datetime.timedelta(
                minutes=i * query_interval + random.uniform(-1, 1)
            )

            event = generate_normal_dns_event(host, timestamp)

            # All hosts query similar pattern of domains
            subdomain = f"node{i % 5}-{random.randint(100, 999)}"
            event["query"] = f"{subdomain}.{cluster_domain}"
            event["record_type"] = cluster_record_type

            # Consistent pattern in answers
            if event["record_type"] == "A" and event["reply_code"] == "NOERROR":
                # Similar C2 IP patterns
                event["answer"] = (
                    f"45.95.{random.randint(1, 5)}.{random.randint(10, 200)}"
                )

            if event["record_type"] == "TXT":
                # Encoded command pattern unique to this cluster
                prefix = "cmd="
                data_length = random.randint(20, 30)
                payload = "".join(
                    random.choice(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
                    )
                    for _ in range(data_length)
                )
                event["answer"] = f'"{prefix}{payload}"'
                event["txt_content"] = f"{prefix}{payload}"

            # Add anomaly type and metadata
            event["anomaly_type"] = "BEHAVIORAL_CLUSTER"
            event["anomaly_description"] = config["description"]
            event["cluster_id"] = 1  # All part of same cluster
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

    print(
        f"Generating baseline activity for {len(hosts)} hosts over {duration_hours} hours..."
    )

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
                server_multiplier = (
                    activity_multiplier * 0.5 + 0.5
                )  # Minimum 50% activity for servers
                queries_this_hour = max(
                    1,
                    int(
                        host["query_rate"]
                        * server_multiplier
                        * random.uniform(0.8, 1.2)
                    ),
                )
            else:
                queries_this_hour = max(
                    1,
                    int(
                        host["query_rate"]
                        * activity_multiplier
                        * random.uniform(0.7, 1.3)
                    ),
                )

            # Generate events for this host for this hour
            for _ in range(queries_this_hour):
                # Check if we've reached the maximum events limit
                if total_events >= max_events:
                    print(f"Reached maximum events limit ({max_events})")
                    return events, host_event_counts

                # Random time within this hour
                event_time = current_hour + datetime.timedelta(
                    minutes=random.randint(0, 59), seconds=random.randint(0, 59)
                )

                # Create the normal DNS event
                event = generate_normal_dns_event(host, event_time)
                events.append(event)
                host_event_counts[host["hostname"]] += 1
                total_events += 1

    print(f"Generated {total_events} baseline events")
    return events, host_event_counts


def main():
    print(
        f"Generating DNS events over {TIME_PERIOD_DAYS} days following Splunk CIM for Network_Resolution..."
    )
    print(f"Optimized for clear detection by Splunk DNSGuard AI macros")

    # Generate the internal hosts
    internal_hosts = generate_internal_hosts()
    print(
        f"Generated {len(internal_hosts)} hosts across {len(DEPARTMENTS)} departments"
    )

    # Set the time range (30 days back from now)
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=TIME_PERIOD_DAYS)

    # Create a list to store all events
    all_events = []

    # Define anomaly types mapping to generator functions
    anomaly_generators = {
        "C2_TUNNELING": generate_c2_tunneling,
        "BEACONING": generate_beaconing,
        "TXT_RECORD_ANOMALY": generate_txt_record_anomaly,
        "ANY_RECORD_ANOMALY": generate_any_record_anomaly,
        "HINFO_RECORD_ANOMALY": generate_hinfo_record_anomaly,
        "AXFR_RECORD_ANOMALY": generate_axfr_record_anomaly,
        "QUERY_LENGTH_ANOMALY": generate_query_length_anomaly,
        "DOMAIN_SHADOWING": generate_domain_shadowing,
    }

    # Map malicious domains to specific anomaly types
    malicious_domain_anomalies = {
        "cryptominer.biz": "ANY_RECORD_ANOMALY",
        "data-exfil.org": "AXFR_RECORD_ANOMALY",
        "fakeupdates.xyz": "BEACONING",
        "malware-payload.net": "C2_TUNNELING",
        "ransomware-delivery.co": "HINFO_RECORD_ANOMALY",
        "evil-c2-server.com": "QUERY_LENGTH_ANOMALY",
        "command-cntr.info": "DOMAIN_SHADOWING",
        "steal-credentials.net": "TXT_RECORD_ANOMALY",
    }

    # Set aside about 75% of the events for baseline
    baseline_max_events = int(MAX_EVENTS * 0.75)

    # Generate baseline normal activity for all hosts
    print("Generating baseline normal DNS activity...")
    baseline_events, host_event_counts = generate_baseline_activity(
        internal_hosts, start_time, end_time, baseline_max_events
    )
    all_events.extend(baseline_events)

    # Select exactly 10 hosts for anomalies (with preference for high-activity hosts)
    anomaly_hosts = sorted(
        internal_hosts, key=lambda h: host_event_counts[h["hostname"]], reverse=True
    )[:ANOMALY_HOSTS]

    # Map each host to exactly one anomaly type
    host_anomaly_map = {}
    anomaly_types = list(anomaly_generators.keys())

    # Ensure critical anomaly types are always included
    critical_anomalies = [
        "HINFO_RECORD_ANOMALY",
        "AXFR_RECORD_ANOMALY",
        "ANY_RECORD_ANOMALY",
    ]
    remaining_anomalies = [a for a in anomaly_types if a not in critical_anomalies]

    # First assign critical anomalies to ensure they're always included
    for i, host in enumerate(anomaly_hosts[: len(critical_anomalies)]):
        host_anomaly_map[host["hostname"]] = [critical_anomalies[i]]

    # Then assign remaining anomalies to other hosts
    for i, host in enumerate(anomaly_hosts[len(critical_anomalies) :]):
        anomaly_type = remaining_anomalies[i % len(remaining_anomalies)]
        host_anomaly_map[host["hostname"]] = [anomaly_type]

    print("\nAnomaly distribution:")
    for hostname, anomaly_types in host_anomaly_map.items():
        print(f"  {hostname}: {', '.join(anomaly_types)}")

    # Keep track of which hosts will participate in behavioral clustering
    behavioral_hosts = []

    # Generate each anomaly type with hosts
    print("\nGenerating anomalies...")

    # First pass - handle all regular anomalies
    # Keep track of malicious domains used by each host
    host_malicious_domains = {}

    for hostname, anomaly_types in host_anomaly_map.items():
        host = next(h for h in internal_hosts if h["hostname"] == hostname)

        for anomaly_type in anomaly_types:
            if anomaly_type == "BEHAVIORAL_CLUSTER":
                # Save these hosts for behavioral clustering
                behavioral_hosts.append(host)
                continue

            # Generate random time for this anomaly (weekdays during business hours)
            random_day = random.randint(
                1, TIME_PERIOD_DAYS - 3
            )  # Avoid very start and end
            anomaly_time = start_time + datetime.timedelta(days=random_day)

            # Ensure weekdays for more realism
            while anomaly_time.weekday() >= 5:  # Skip weekends
                anomaly_time += datetime.timedelta(days=1)

            # Set business hours (9am-6pm)
            anomaly_time = anomaly_time.replace(
                hour=random.randint(9, 18), minute=random.randint(0, 59)  # 9am-6pm
            )

            # Select a malicious domain for this host based on the anomaly type
            # Find a domain that matches this anomaly type
            matching_domains = [
                domain
                for domain, anomaly in malicious_domain_anomalies.items()
                if anomaly == anomaly_type
            ]
            if matching_domains:
                host_malicious_domains[hostname] = random.choice(matching_domains)
            else:
                # If no domain matches this anomaly type, use a random one
                host_malicious_domains[hostname] = random.choice(MALICIOUS_DOMAINS)

            # Generate the anomaly
            generator_func = anomaly_generators[anomaly_type]
            anomaly_events = generator_func(host, anomaly_time)

            # Update all events to use the assigned malicious domain
            for event in anomaly_events:
                if "query" in event and any(
                    domain in event["query"] for domain in MALICIOUS_DOMAINS
                ):
                    # Replace any existing malicious domain with the assigned one
                    for domain in MALICIOUS_DOMAINS:
                        if domain in event["query"]:
                            event["query"] = event["query"].replace(
                                domain, host_malicious_domains[hostname]
                            )

            all_events.extend(anomaly_events)
            print(
                f"  Generated {len(anomaly_events)} events for {anomaly_type} on host {hostname} using domain {host_malicious_domains[hostname]}"
            )

    # Second pass - handle behavioral clustering if needed
    if behavioral_hosts:
        print("\nGenerating behavioral cluster across multiple hosts...")
        # Use a common time for the cluster
        cluster_day = random.randint(5, TIME_PERIOD_DAYS - 5)
        cluster_time = start_time + datetime.timedelta(days=cluster_day)
        cluster_time = cluster_time.replace(
            hour=random.randint(10, 14), minute=random.randint(0, 30)
        )

        # Get all hosts if we need more for the cluster
        if len(behavioral_hosts) < ANOMALY_CONFIG["BEHAVIORAL_CLUSTER"]["cluster_size"]:
            other_hosts = [h for h in anomaly_hosts if h not in behavioral_hosts]
            behavioral_hosts.extend(
                other_hosts[
                    : ANOMALY_CONFIG["BEHAVIORAL_CLUSTER"]["cluster_size"]
                    - len(behavioral_hosts)
                ]
            )

        cluster_events = generate_behavioral_cluster(behavioral_hosts, cluster_time)
        all_events.extend(cluster_events)

        print(
            f"  Generated {len(cluster_events)} events for behavioral cluster across {len(behavioral_hosts)} hosts"
        )

    # Sort all events by timestamp
    print("\nSorting events by timestamp...")
    all_events.sort(key=lambda x: x["timestamp"])

    # Write events to file in JSON format
    print(f"Writing {len(all_events)} events to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    # Create a summary file with details about the anomalies
    print("Creating summary report...")
    with open("dns_events_summary.txt", "w") as f:
        f.write(
            "====================================================================\n"
        )
        f.write(
            "         SPLUNK DNSGUARD AI - TEST DATASET DOCUMENTATION            \n"
        )
        f.write(
            "====================================================================\n\n"
        )
        f.write(f"Total DNS events generated: {len(all_events)}\n")
        f.write(
            f"Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # Count events by anomaly type
        anomaly_counts = defaultdict(int)
        normal_count = 0

        for event in all_events:
            if "anomaly_type" in event:
                anomaly_counts[event["anomaly_type"]] += 1
            else:
                normal_count += 1

        f.write("EVENT COUNTS BY TYPE:\n")
        f.write(f"- Normal DNS events: {normal_count}\n")
        for anomaly_type, count in sorted(anomaly_counts.items()):
            anomaly_description = next(
                (
                    event["anomaly_description"]
                    for event in all_events
                    if "anomaly_type" in event and event["anomaly_type"] == anomaly_type
                ),
                "",
            )
            f.write(f"- {anomaly_type}: {count} events - {anomaly_description}\n")

        f.write("\nANOMALOUS HOSTS AND THEIR MALICIOUS DOMAINS:\n")
        for hostname, anomaly_types in host_anomaly_map.items():
            host_info = next(
                (h for h in internal_hosts if h["hostname"] == hostname), None
            )
            if host_info:
                anomalies_str = ", ".join(anomaly_types)
                malicious_domain = host_malicious_domains.get(hostname, "N/A")
                f.write(
                    f"- {hostname} ({host_info['ip']}, {host_info['department']}):\n"
                    f"  Anomaly Type: {anomalies_str}\n"
                    f"  Malicious Domain: {malicious_domain}\n"
                )

        f.write("\nSPLUNK DETECTION METHODS:\n")
        f.write(
            "Each anomaly type is designed to trigger specific Splunk detection macros in DNSGuard AI:\n\n"
        )
        f.write("1. C2 Tunneling: `dns_c2_tunneling_detection`\n")
        f.write(
            "   Description: High volume of DNS queries from single host within short time period\n"
        )
        f.write(
            "   Detection: Uses density function to find hourly query count outliers by src\n\n"
        )

        f.write("2. Beaconing: `dns_beaconing_detection`\n")
        f.write(
            "   Description: Periodic DNS queries at regular intervals with minimal time variation\n"
        )
        f.write(
            "   Detection: Analyzes consistency of time gaps between queries to same domain\n\n"
        )

        f.write("4. TXT Record Anomalies: `dns_txt_record_detection`\n")
        f.write(
            "   Description: Unusual volume of TXT record queries with encoded content\n"
        )
        f.write("   Detection: Identifies outliers in TXT record usage by host\n\n")

        f.write("5. ANY Record Anomalies: `dns_any_record_detection`\n")
        f.write(
            "   Description: Unusual volume of ANY record queries indicating potential reconnaissance\n"
        )
        f.write("   Detection: Identifies outliers in ANY record usage by host\n\n")

        f.write("6. HINFO Record Anomalies: `dns_hinfo_record_detection`\n")
        f.write(
            "   Description: Unusual HINFO record queries for system information gathering\n"
        )
        f.write("   Detection: Identifies outliers in HINFO record usage by host\n\n")

        f.write("7. AXFR Record Anomalies: `dns_axfr_record_detection`\n")
        f.write("   Description: Zone transfer attempts using AXFR queries\n")
        f.write("   Detection: Identifies outliers in AXFR record usage by host\n\n")

        f.write("8. Query Length Anomalies: `dns_query_length_detection`\n")
        f.write(
            "   Description: Abnormally long DNS query strings indicating potential data exfiltration\n"
        )
        f.write("   Detection: Identifies outliers in query string length by host\n\n")

        f.write("9. Domain Shadowing: `dns_domain_shadowing_detection`\n")
        f.write(
            "   Description: Excessive unique subdomains for a single parent domain\n"
        )
        f.write(
            "   Detection: Measures distinct subdomain count by parent domain and identifies outliers\n\n"
        )

        f.write("10. Behavioral Clustering: `dns_behavioral_clustering_detection`\n")
        f.write(
            "   Description: Multiple hosts exhibiting synchronized suspicious DNS behavior\n"
        )
        f.write(
            "   Detection: Uses KMeans clustering on multiple DNS behavior features\n\n"
        )

        f.write(
            "====================================================================\n"
        )
        f.write(
            "This dataset has been optimized to clearly demonstrate each detection method.\n"
        )
        f.write(
            "The anomalies are more pronounced than would typically be seen in the wild,\n"
        )
        f.write("making this dataset ideal for testing and demonstration purposes.\n")
        f.write(
            "====================================================================\n"
        )

    print(f"Generated {len(all_events)} DNS events and saved to {OUTPUT_FILE}")
    print(f"Summary saved to dns_events_summary.txt")


if __name__ == "__main__":
    main()
