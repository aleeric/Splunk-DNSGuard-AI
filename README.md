# Splunk DNS Guard AI
A comprehensive DNS anomaly detection system using Splunk and machine learning to identify malicious DNS activity in enterprise networks.

![](imgs/banner.gif)

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Author-Riccardo%20Alesci-blue.svg" alt="Author: Riccardo Alesci"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Splunk-8.0%2B-green.svg" alt="Splunk 8.0+"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Python-3.6%2B-blue.svg" alt="Python 3.6+"/></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"/></a>
</p>

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Methods](#detection-methods)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview

DNS Guard AI is a Splunk App designed to detect various types of DNS anomalies that could indicate malicious activity such as command and control (C2) communication, data exfiltration, or reconnaissance. The system uses Splunk's powerful search capabilities combined with machine learning techniques to identify patterns that deviate from normal DNS behavior.

### Key Benefits
- **Real-time Detection**: Continuous monitoring of DNS traffic for immediate threat identification
- **Comprehensive Analysis**: Multiple detection methods working in concert to identify various types of threats
- **Machine Learning Integration**: Advanced algorithms for pattern recognition and anomaly detection
- **Enterprise-Ready**: Scalable solution designed for large network environments
- **CIM Compliance**: Fully compatible with Splunk's Common Information Model

## Project Structure

```
├── poc/                       # Contains the Proof of Concept implementation
│   └── generate_dns_events.py # Script to generate synthetic DNS data
├── Splunk-DNSGuard-AI/        # Main application directory
│   ├── default/               # Default configuration files
│   │   ├── app.conf           # App configuration
│   │   ├── collections.conf   # Collections configuration
│   │   ├── macros.conf        # Macros configurations
│   │   ├── risk_factors.conf  # Risk Factors configurations
│   │   └── savedsearches.conf # Saved search configurations
│   │   └── transforms.conf    # Transforms configurations
│   └── static/                # Static resources
│       └── appIcon*           # App icons
```

## Features

| Detection Method                  | DNS Anomaly                             
|-----------------------------------|-----------------------------------------
| Beaconing                         | Detects regular, periodic DNS queries typical of C2 communication
| C2 Tunneling                      | Identifies hosts making an unusually high number of DNS queries         
| Query Length Anomalies            | Identifies unusually long DNS queries (potential data exfiltration)  
| Domain Shadowing                  | Detects many unique subdomains for a legitimate domain  
| TXT Record Anomalies              | Detects unusual use of TXT records for data exfiltration               
| ANY Record Anomalies              | Identifies reconnaissance activity using ANY queries               
| HINFO Record Anomalies            | Identifies reconnaissance activity using HINFO queries              
| AXFR Record Anomalies             | Identifies reconnaissance activity using AXFR queries                
| Behavioral Clustering             | Groups hosts with similar abnormal DNS behavior              


## Getting Started

### Prerequisites

#### 🐍 Python Requirements
- **Python Version**: 3.6 or higher
- **Core Packages**:
  ```bash
  datetime  # For timestamp handling
  random    # For data generation
  json      # For data serialization
  collections # For advanced data structures
  ```

#### 🔍 Splunk Requirements
- **Splunk Enterprise / Splunk Cloud**: Version 8.0 or higher
- **Essential Apps**:
  - [Splunk Common Information Model (CIM)](https://splunkbase.splunk.com/app/1621)
  - [Splunk Machine Learning Toolkit](https://splunkbase.splunk.com/app/2890)
  - **Python for Scientific Computing**:
    - [Mac](https://splunkbase.splunk.com/app/2881/)
    - [Linux 64-bit](https://splunkbase.splunk.com/app/2882/)
    - [Windows 64-bit](https://splunkbase.splunk.com/app/2883/)

#### ⭐ Recommended Additions
- [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263) for enhanced security monitoring capabilities


## Usage

### Generating Synthetic Data

The `generate_dns_events.py` script creates a comprehensive dataset of DNS query events for testing and demonstrating DNSGuard-AI's anomaly detection capabilities:

```bash
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

### Using the Splunk App

1. Import the generated data into Splunk:
   ```bash
   splunk add oneshot -index dns -sourcetype dns -source dns_events.json
   ```

2. Navigate to the DNS Guard AI dashboard in Splunk
3. Use the provided searches to detect anomalies
4. Each anomaly will clearly trigger its corresponding detection macro


5. Generate synthetic DNS data:
   ```bash
   cd poc
   python generate_dns_events.py
   ```

6. Install the Splunk app:
   - Copy the `Splunk-DNSGuard-AI` directory to your Splunk apps directory
   - Restart Splunk or reload the app through the web interface

## Detection Methods Details

## Acknowledgments

- Optimized to demonstrate Splunk's machine learning capabilities for DNS threat detection
- Uses Splunk's Common Information Model (CIM) for Network Resolution