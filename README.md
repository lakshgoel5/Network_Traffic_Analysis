# Network Traffic Analysis

A comprehensive network traffic analysis tool for capturing, analyzing, and visualizing network performance metrics including throughput and round-trip time (RTT).

## Table of Contents

1. [About the Project](#about-the-project)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [How to Run](#how-to-run)
5. [Analysis Results](#analysis-results)
6. [Key Findings](#key-findings)
7. [Conclusion](#conclusion)
8. [Author](#author)

## About the Project

This project implements a Python-based network traffic analysis tool developed as part of COL 334/672 Assignment 1: "Getting To Know Network Traffic". The tool performs the following functions:

- **Traffic Capture**: Uses `tshark` to capture network traffic between client and server endpoints
- **Throughput Analysis**: Calculates and plots upload/download throughput over time
- **RTT Analysis**: Measures and visualizes round-trip time for TCP packets
- **Protocol Comparison**: Analyzes performance differences between HTTP and HTTPS traffic

The assignment explored fundamental network measurement tools (ping, traceroute) and traffic analysis techniques, providing insights into network protocols, security measures, and performance characteristics.

## Requirements

### System Requirements

- Python 3.x
- `tshark` (part of Wireshark package)
- Unix-like operating system (macOS, Linux)

### Python Dependencies

The following Python packages are required:

```
dpkt>=1.9.8
matplotlib>=3.5.0
```

Additional standard library modules used:
- `os` - System operations
- `subprocess` - Running tshark commands
- `sys` - System exit handling
- `argparse` - Command-line argument parsing
- `socket` - IP address handling

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/lakshgoel5/Network_Traffic_Analysis.git
   cd Network_Traffic_Analysis
   ```

2. **Install Python dependencies**:
   ```bash
   pip install dpkt matplotlib
   ```

3. **Install tshark** (if not already installed):
   
   **macOS**:
   ```bash
   brew install wireshark
   ```
   
   **Ubuntu/Debian**:
   ```bash
   sudo apt-get update
   sudo apt-get install tshark
   ```

## How to Run

The `traffic_analysis.py` script can operate in two modes: traffic capture and traffic analysis.

### Basic Command Structure

```bash
python3 traffic_analysis.py --client <CLIENT_IP> --server <SERVER_IP> [OPTIONS]
```

### Command-Line Arguments

- `--client`: **Required** - Client IP address
- `--server`: **Required** - Server IP address
- `--file`: Output/input filename for captured traffic (default: `traffic.pcap`)
- `--throughput`: Perform throughput analysis
- `--down`: Analyze download throughput (use with `--throughput`)
- `--up`: Analyze upload throughput (use with `--throughput`)
- `--rtt`: Perform round-trip time analysis

### Usage Examples

#### 1. Capture Traffic (if pcap file doesn't exist)

If the specified file doesn't exist, the script will automatically capture traffic:

```bash
python3 traffic_analysis.py --client 192.168.1.100 --server 93.184.216.34 --file traffic.pcap
```

**Note**: You'll need to visit the server IP in your browser during the 60-second capture window.

#### 2. Analyze Download Throughput

```bash
python3 traffic_analysis.py --client <CLIENT_IP> --server <SERVER_IP> --file http.pcap --throughput --down
```

This generates `down_throughput.png` showing bytes transferred per second.

#### 3. Analyze Upload Throughput

```bash
python3 traffic_analysis.py --client <CLIENT_IP> --server <SERVER_IP> --file http.pcap --throughput --up
```

This generates `up_throughput.png` showing bytes uploaded per second.

#### 4. Analyze Round-Trip Time (RTT)

```bash
python3 traffic_analysis.py --client <CLIENT_IP> --server <SERVER_IP> --file http.pcap --rtt
```

This generates `rtt.png` plotting RTT values over time.

### Example Workflow

For analyzing HTTP traffic:

```bash
# Analyze download throughput
python3 traffic_analysis.py --client 192.168.1.100 --server 93.184.216.34 --file http.pcap --throughput --down

# Analyze upload throughput
python3 traffic_analysis.py --client 192.168.1.100 --server 93.184.216.34 --file http.pcap --throughput --up

# Analyze RTT
python3 traffic_analysis.py --client 192.168.1.100 --server 93.184.216.34 --file http.pcap --rtt
```

## Analysis Results

The analysis was performed on traffic captures from `http://www.httpvshttps.com` (HTTP) and `https://www.httpvshttps.com` (HTTPS). Detailed results are available in `2023CS10848_Networks_Assignment1.pdf`.

### Methodology

The Python script implements the following analysis techniques:

1. **Throughput Analysis**: 
   - Creates a dictionary mapping discrete time intervals to bytes transferred/received
   - Calculates throughput over 1-second windows
   - Generates time-series plots

2. **RTT Calculation**:
   - Matches TCP acknowledgments with sent packets using sequence numbers
   - Formula: ACK = SEQ + Packet_Length
   - Stores timestamps with corresponding RTT values
   - Plots RTT distribution over time

### Performance Comparison: HTTP vs HTTPS

#### Download Throughput

| Metric | HTTP | HTTPS |
|--------|------|-------|
| Total Download | 44 MB | 17.5 MB |
| Page Load Time | 17.6 seconds | 4.6 seconds |
| Throughput Duration | ~19 seconds | ~5 seconds |

**Key Observations**:
- HTTPS demonstrated significantly higher download throughput
- HTTPS loaded nearly **4x faster** than HTTP (4.6s vs 17.6s)
- Download throughput plots show HTTPS sustained higher data transfer rates

#### Upload Throughput

Both HTTP and HTTPS showed comparable upload patterns, with HTTPS maintaining more consistent upload rates due to persistent TLS connections.

#### Round-Trip Time (RTT)

RTT measurements for both protocols showed:
- Similar RTT ranges for both HTTP and HTTPS
- HTTPS maintained more stable RTT values due to connection reuse
- HTTP showed more variability due to multiple TCP connection establishments

### Traffic Capture Analysis (Wireshark)

#### HTTP Traffic (`http.pcap`)

1. **DNS Resolution**: Request-response completed in milliseconds
2. **HTTP Requests**: Over 700 HTTP requests generated to render the complete webpage
3. **TCP Connections**: Multiple connections used, with content fetched over persistent connections
4. **Visibility**: All HTTP requests, responses, HTML, and JavaScript files were visible in plain text

#### HTTPS Traffic (`https.pcap`)

1. **DNS Resolution**: Similar to HTTP case
2. **Encrypted Traffic**: No HTTP packets visible; all application data encrypted within TLS records
3. **TCP Connections**: Fewer connections required due to persistent TLS sessions
4. **Content Protection**: HTML/JavaScript files not directly observable; only encrypted data flows visible

### Key Differences

The analysis revealed critical differences between HTTP and HTTPS:

**Security**:
- HTTP: All data visible in plain text (vulnerable to eavesdropping)
- HTTPS: Complete encryption of application-layer data (confidentiality guaranteed)

**Performance**:
- HTTP: Lower throughput, longer load times
- HTTPS: Higher throughput, significantly faster load times (4.6s vs 17.6s)

**Efficiency**:
- HTTP: Multiple TCP connections for different resources
- HTTPS: Persistent TLS sessions efficiently handle multiple requests

**Architecture**:
- HTTP: Simple request-response without encryption overhead
- HTTPS: TLS encryption provides confidentiality, integrity, and authentication

## Key Findings

1. **HTTPS Performance Advantage**: Contrary to common assumptions, HTTPS was significantly faster than HTTP (4x improvement in page load time), demonstrating that modern TLS implementations add minimal overhead while providing security benefits.

2. **Throughput Impact**: Higher download throughput in HTTPS directly correlated with reduced page load times, showing the importance of efficient data transfer in web performance.

3. **Connection Efficiency**: HTTPS required fewer TCP connections due to persistent TLS sessions, reducing connection establishment overhead.

4. **Security vs Performance**: The analysis demonstrated that security (HTTPS) and performance are not mutually exclusive - HTTPS provided both better security and better performance.

5. **Protocol Multiplicity**: A single webpage requires hundreds of HTTP requests for images, scripts, stylesheets, and other resources, managed through a smaller number of persistent TCP connections.

6. **Network Measurement Tools**: The assignment demonstrated the value of fundamental tools like ping, traceroute, and packet capture in understanding network behavior and performance.

## Conclusion

This project provided a comprehensive analysis of network traffic and performance using fundamental measurement tools. The investigation revealed key insights into how network architecture, protocols, and security measures impact the end-user experience.

**Key Takeaways**:

- **Modern Security is Efficient**: HTTPS not only provides essential security features but also delivers superior performance through optimized implementations and connection reuse.

- **Measurement Tools Matter**: Tools like ping, traceroute, Wireshark, and programmatic packet analysis are essential for understanding network behavior and diagnosing performance issues.

- **Protocol Design Impact**: The design choices in network protocols (like TLS session persistence) have significant impacts on real-world performance.

- **Content Delivery Optimization**: The use of CDNs and distributed architectures (as demonstrated in the ping/traceroute exercises) provides substantial performance benefits compared to centralized servers.

The analysis quantitatively confirmed that the HTTPS connection was not only more secure but also significantly more efficient, achieving a substantially higher download throughput and resulting in a page load time nearly four times faster than its unencrypted HTTP counterpart.

## Author

**Laksh Goel**  
Roll Number: 2023CS10848  
Course: COL 334/672 - Computer Networks  
Assignment: Programming Assignment 1 - Getting To Know Network Traffic
