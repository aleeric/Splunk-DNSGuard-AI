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

- **Organization Simulation**: Creates 100 hosts across 7 departments (IT, Engineering, Sales, Marketing, Finance, HR, and Servers) with realistic IP addressing and naming conventions
- **Timeframe**: Generates 30 days of DNS activity with realistic workday/weekend and time-of-day patterns
- **Volume Control**: Limits total events to under 1 million for manageable processing
- **Realistic Baseline**: Normal DNS traffic follows typical enterprise patterns with domain popularity weights and department-specific behavior

#### Anomaly Generation

The script strategically distributes exactly 10 anomalies across select hosts:
- 2 hosts with 3 anomalies each
- 2 hosts with 2 anomalies each  
- 3 hosts involved in coordinated behavioral clustering
- All anomalies occur during business hours on weekdays for realistic detection scenarios

#### Output Files

The script generates two files:
- **dns_events.json**: The main dataset containing all DNS events in JSON format (Splunk CIM compliant)
- **dns_events_summary.txt**: A detailed summary of generated events, anomaly distributions, affected hosts, and detection methods

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