# Splunk DNS Guard AI

A comprehensive DNS anomaly detection system using Splunk and machine learning to identify malicious DNS activity in enterprise networks.

## Overview

DNS Guard AI is a proof-of-concept (POC) system designed to detect various types of DNS anomalies that could indicate malicious activity such as command and control (C2) communication, data exfiltration, or reconnaissance. The system uses Splunk's powerful search capabilities combined with machine learning techniques to identify patterns that deviate from normal DNS behavior.

## Project Structure

```
Splunk-DNSGuard-AI/
├── poc/                      # Proof of Concept implementation
│   ├── generate_dns_events.py # Synthetic DNS data generator
│   └── dns_events.json       # Generated DNS events (output)
├── splunk/                   # Splunk implementation
│   ├── app/                  # Splunk app files
│   │   ├── bin/              # Scripts and executables
│   │   ├── default/          # Default configuration
│   │   ├── local/            # Local configuration
│   │   └── metadata/         # App metadata
│   └── README.md             # Splunk app documentation
└── README.md                 # This file
```

## Features

The system detects 12 different types of DNS anomalies:

1. **Volume and Frequency Anomalies**: Identifies hosts making an unusually high number of DNS queries
2. **Beaconing Detection**: Detects regular, periodic DNS queries typical of C2 communication
3. **Burst Activity Detection**: Identifies sudden spikes in DNS query volume
4. **TXT Record Type Anomalies**: Detects unusual use of TXT records for data exfiltration
5. **ANY Record Type Anomalies**: Identifies reconnaissance activity using ANY queries
6. **Record Type Rarity Analysis**: Detects use of rare DNS record types
7. **Query Length Anomalies**: Identifies unusually long DNS queries (potential data exfiltration)
8. **Domain Shadowing Detection**: Detects many unique subdomains for a legitimate domain
9. **Behavioral Clustering**: Groups hosts with similar abnormal DNS behavior
10. **High Priority Combined Anomalies**: Correlates multiple anomaly indicators
11. **DNS C2 Comprehensive Detection**: Identifies full C2 communication patterns
12. **DNS Tunneling Detection**: Detects data exfiltration via DNS tunneling

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

## Detection Methods

The system uses various detection methods based on academic research:

1. **Volume/Frequency Anomalies**: DensityFunction on query count by source
2. **Beaconing**: Calculate gaps between queries and check for low standard deviation
3. **Burst Activity**: Use streamstats time_window to detect sudden spikes
4. **TXT Record Anomalies**: Monitor for abnormal usage of TXT records by source
5. **ANY Record Anomalies**: Look for hosts using ANY queries (often used in recon)
6. **Record Type Rarity**: Find hosts using statistically rare record types
7. **Query Length Anomalies**: Calculate query length and use DensityFunction to find outliers
8. **Domain Shadowing**: Count unique subdomains per parent domain and look for anomalies
9. **Behavioral Clustering**: Apply KMeans clustering to multiple DNS behavior metrics
10. **High Priority Combined**: Correlate multiple anomaly indicators for high confidence
11. **DNS C2**: Look for beaconing combined with data exchange through DNS
12. **DNS Tunneling**: Identify excessively long queries, high volume, and data transfer

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on academic research in DNS anomaly detection
- Inspired by real-world DNS-based malware and C2 techniques
- Uses Splunk's Common Information Model (CIM) for Network Resolution 