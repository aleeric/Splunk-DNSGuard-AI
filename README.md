# Splunk DNS Guard AI
A comprehensive DNS anomaly detection system using Splunk and machine learning to identify malicious DNS activity in enterprise networks.

![](imgs/banner.gif)

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Author-Riccardo%20Alesci-blue.svg" alt="Author: Riccardo Alesci"/></a>
</p>



## Overview

DNS Guard AI is a Splunk App designed to detect various types of DNS anomalies that could indicate malicious activity such as command and control (C2) communication, data exfiltration, or reconnaissance. The system uses Splunk's powerful search capabilities combined with machine learning techniques to identify patterns that deviate from normal DNS behavior.

## Project Structure

```
├── poc/                       # Contains the Proof of Concept implementation
│   └── generate_dns_events.py # Script to generate synthetic DNS data
├── Splunk-DNSGuard-AI/        # Main application directory
│   ├── default/               # Default configuration files
│   └── lookups/               # Lookup tables for data enrichment
```

## Features

| Detection Method                  | DNS Anomaly                             | Implemented |
|-----------------------------------|-----------------------------------------|:-----------:|
| C2 Tunneling        | Identifies hosts making an unusually high number of DNS queries         | ✅          |
| Beaconing                         | Detects regular, periodic DNS queries typical of C2 communication                     | ✅          |
| Burst Activity                    | Identifies sudden spikes in DNS query volume                | ✅          |
| TXT Record Anomalies              | Detects unusual use of TXT records for data exfiltration               | ✅          |
| ANY Record Anomalies              | Identifies reconnaissance activity using ANY queries               | ✅          |
| HINFO Record Anomalies              | Identifies reconnaissance activity using HINFO queries               | ✅          |
| AXFR Record Anomalies              | Identifies reconnaissance activity using AXFR queries               | ✅          |
| Query Length Anomalies            | Identifies unusually long DNS queries (potential data exfiltration)                  | ✅          |
| Domain Shadowing                  | Detects many unique subdomains for a legitimate domain              | ✅          |
| Behavioral Clustering             | Groups hosts with similar abnormal DNS behavior                   | ✅          |


## Getting Started

### Prerequisites

- Python 3.6+
- Splunk Enterprise 8.0+ (for the Splunk implementation)
- Required Python packages: `datetime`, `random`, `json`, `collections`

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/aleeric/Splunk-DNSGuard-AI.git
   cd Splunk-DNSGuard-AI
   ```

2. Generate synthetic DNS data:
   ```
   cd poc
   python generate_dns_events.py
   ```

3. Install the Splunk app:
   - Copy the `splunk/app` directory to your Splunk apps directory
   - Restart Splunk or reload the app

## Usage

### Generating Synthetic Data

The `generate_dns_events.py` script creates a comprehensive dataset of DNS query events for testing and demonstrating DNSGuard-AI's anomaly detection capabilities:

```
python poc/generate_dns_events.py
```

#### Key Features

- **Optimized for Detection**: Each anomaly is specifically engineered to trigger the corresponding Splunk detection macro
- **Advanced Configuration**: Parametrized anomaly generation with precise control over event volume, timing, and patterns
- **Organization Simulation**: Creates 100 hosts across 7 departments with realistic IP addressing and naming conventions
- **Timeframe**: Generates 30 days of DNS activity with realistic workday/weekend and time-of-day patterns
- **CIM Compliance**: All events follow Splunk's Common Information Model for Network Resolution

#### Enhanced Anomaly Generation

Each anomaly type is carefully designed to match the detection pattern used in the Splunk macros:

- **C2 Tunneling**: High volume of DNS queries concentrated in hourly windows to trigger density-based outlier detection
- **Beaconing**: Precisely timed queries with minimal jitter to establish clear communication patterns
- **Burst Activity**: Intense query volume in very short time windows (under 60 seconds)
- **TXT Record Anomalies**: Suspicious encoded content in TXT records with command-like prefixes
- **ANY/HINFO/AXFR Records**: Targeted use of rare record types for reconnaissance
- **Query Length Anomalies**: Extremely long DNS queries exceeding threshold limits
- **Domain Shadowing**: Large number of unique subdomains for a single parent domain
- **Behavioral Clustering**: Multiple hosts exhibiting synchronized suspicious DNS patterns

The script guarantees all 10 anomaly types are represented and distributed across 5 hosts, with each host having 2 distinct anomaly types.

#### Output Files

The script generates two files:
- **dns_events.json**: The main dataset containing all DNS events in JSON format (Splunk CIM compliant)
- **dns_events_summary.txt**: A detailed report including:
  - Total event counts and time ranges
  - Breakdown of events by type
  - List of anomalous hosts with their assigned anomalies
  - Description of each detection method and its corresponding Splunk macro
  - Technical details of how each detection method works

### Using the Splunk App

1. Import the generated data into Splunk:
   ```
   splunk add oneshot -index dns -sourcetype dns -source dns_events.json
   ```

2. Navigate to the DNS Guard AI dashboard in Splunk
3. Use the provided searches to detect anomalies
4. Each anomaly will clearly trigger its corresponding detection macro

## Detection Methods Details

| Detection Method | Description | Detection Technique |
|------------------|-------------|---------------------|
| C2 Tunneling | High volume DNS queries from a single host | Uses density function to find hourly query count outliers by src |
| Beaconing | Periodic DNS queries at regular intervals | Analyzes consistency of time gaps between queries to same domain |
| Burst Activity | Sudden spike in DNS queries in short timeframe | Measures max burst count per minute using sliding time windows |
| TXT Record Anomalies | Unusual volume/content of TXT records | Identifies outliers in TXT record usage and analyzes content |
| ANY Record Anomalies | Unusual use of ANY record type | Identifies outliers in ANY record usage by host |
| HINFO Record Anomalies | Unusual use of HINFO record type | Identifies outliers in HINFO record usage by host |
| AXFR Record Anomalies | Zone transfer attempts | Identifies outliers in AXFR record usage by host |
| Query Length Anomalies | Abnormally long DNS queries | Identifies outliers in query string length by host |
| Domain Shadowing | Excessive unique subdomains for single domain | Measures distinct subdomain count by parent domain and identifies outliers |
| Behavioral Clustering | Multiple hosts with similar suspicious patterns | Uses KMeans clustering on multiple DNS behavior features |

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Optimized to demonstrate Splunk's machine learning capabilities for DNS threat detection
- Uses Splunk's Common Information Model (CIM) for Network Resolution
- Designed for clear demonstration and educational purposes 