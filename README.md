# Splunk DNS Guard AI

![](imgs/banner.gif)

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Author-Riccardo%20Alesci-blue.svg" alt="Author: Riccardo Alesci"/></a>
</p>

A comprehensive DNS anomaly detection system using Splunk and machine learning to identify malicious DNS activity in enterprise networks.

## Overview

DNS Guard AI is a Splunk App designed to detect various types of DNS anomalies that could indicate malicious activity such as command and control (C2) communication, data exfiltration, or reconnaissance. The system uses Splunk's powerful search capabilities combined with machine learning techniques to identify patterns that deviate from normal DNS behavior.

## Project Structure

```
Splunk-DNSGuard-AI/
├── poc/                       # Contains the Proof of Concept implementation
│   └── generate_dns_events.py # Script to generate synthetic DNS data
├── Splunk-DNSGuard-AI/        # Main application directory
│   ├── default/               # Default configuration files
│   └── lookups/               # Lookup tables for data enrichment
├── .gitignore                 # Git ignore file
├── dns_events_summary.txt     # Summary of generated DNS events
├── dns_events.json            # Main dataset with DNS events
└── README.md                  # Documentation file
```

## Features

| DNS Anomaly                             | Description                                                   | Implemented |
|-----------------------------------------|---------------------------------------------------------------|:-----------:|
| Volume and Frequency Anomalies          | Identifies hosts making an unusually high number of DNS queries | ❌          |
| Beaconing Detection                     | Detects regular, periodic DNS queries typical of C2 communication | ✅          |
| Burst Activity Detection                | Identifies sudden spikes in DNS query volume                   | ❌          |
| TXT Record Type Anomalies               | Detects unusual use of TXT records for data exfiltration       | ❌          |
| ANY Record Type Anomalies               | Identifies reconnaissance activity using ANY queries            | ❌          |
| Record Type Rarity Analysis             | Detects use of rare DNS record types                            | ❌          |
| Query Length Anomalies                  | Identifies unusually long DNS queries (potential data exfiltration) | ❌          |
| Domain Shadowing Detection              | Detects many unique subdomains for a legitimate domain          | ❌          |
| Behavioral Clustering                   | Groups hosts with similar abnormal DNS behavior                 | ❌          |
| High Priority Combined Anomalies        | Correlates multiple anomaly indicators                          | ❌          |
| DNS C2 Comprehensive Detection          | Identifies full C2 communication patterns                      | ❌          |
| DNS Tunneling Detection                 | Detects data exfiltration via DNS tunneling                    | ❌          |

## Detection Methods

| Detection Method                  | Description                                                   | Implemented |
|-----------------------------------|---------------------------------------------------------------|:-----------:|
| Volume/Frequency Anomalies        | DensityFunction on query count by source                      | ❌          |
| Beaconing                         | Calculate gaps between queries and check for low standard deviation | ✅          |
| Burst Activity                    | Use streamstats time_window to detect sudden spikes            | ❌          |
| TXT Record Anomalies              | Monitor for abnormal usage of TXT records by source           | ❌          |
| ANY Record Anomalies              | Look for hosts using ANY queries (often used in recon)        | ❌          |
| Record Type Rarity                | Find hosts using statistically rare record types              | ❌          |
| Query Length Anomalies            | Calculate query length and use DensityFunction to find outliers | ❌          |
| Domain Shadowing                  | Count unique subdomains per parent domain and look for anomalies | ❌          |
| Behavioral Clustering             | Apply KMeans clustering to multiple DNS behavior metrics      | ❌          |
| High Priority Combined            | Correlate multiple anomaly indicators for high confidence      | ❌          |
| DNS C2                            | Look for beaconing combined with data exchange through DNS     | ❌          |
| DNS Tunneling                     | Identify excessively long queries, high volume, and data transfer | ❌          |

## Getting Started

### Prerequisites

- Python 3.6+
- Splunk Enterprise 8.0+ (for the Splunk implementation)
- Required Python packages: `datetime`, `random`, `json`, `collections`

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/Splunk-DNSGuard-AI.git
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

The `generate_dns_events.py` script creates a realistic dataset with:
- 90 days of DNS activity
- 500 internal hosts (70% Windows, 30% Linux)
- Normal DNS behavior for all hosts
- 12 specific hosts with different anomaly types
- Anomalies distributed randomly throughout the 90-day period

Run the script to generate the data:
```
python generate_dns_events.py
```

The script will create:
- `dns_events.json`: The main dataset with all DNS events
- `dns_events_summary.txt`: A summary of the generated data and anomalies

### Using the Splunk App

1. Import the generated data into Splunk:
   ```
   splunk add oneshot -index dns -sourcetype dns -source dns_events.json
   ```

2. Navigate to the DNS Guard AI dashboard in Splunk
3. Use the provided searches to detect anomalies

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by real-world DNS-based malware and C2 techniques
- Uses Splunk's Common Information Model (CIM) for Network Resolution 