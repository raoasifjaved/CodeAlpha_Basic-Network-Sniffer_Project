# CodeAlpha_Basic-Network-Sniffer_Project
Educational Python &amp; Scapy network sniffer for capturing and analyzing packet metadata, protocols, IPs, packet structure, and controlled payload previews through a Streamlit interface.
🌐 NetScope — Basic Network Sniffer

NetScope is an educational network traffic analysis tool built with Python, Scapy, and Streamlit. It allows users to capture authorized network traffic, load PCAP/PCAPNG files, inspect packet structure, identify protocols, and analyze source/destination network information through an interactive web interface.

The project was developed to strengthen practical understanding of computer networking, packet structures, protocol layers, and basic network-security concepts.

 ✨ Key Features

- Live packet capture using Scapy
- PCAP/PCAPNG offline analysis
- Safe Demo Traffic mode
- Source and destination IP identification
- TCP, UDP, ICMP, IPv4 and IPv6 detection
- Packet length and header information
- Layer-by-layer packet structure inspection
- Optional truncated payload preview
- Protocol statistics and endpoint analysis
- Interactive Streamlit dashboard
- CSV, JSON and Markdown export
- Built-in checks for reliable packet parsing

🛠️ Technology Stack

Python  
Scapy  
Streamlit  
Pandas  
Python-dotenv

🎯 Learning Objectives

This project focuses on understanding:

- How network packets are captured
- How protocol layers are represented
- How source and destination information is carried
- Differences between common transport protocols
- Basic packet inspection and traffic analysis
- Practical use of Python for networking

🔐 Security & Responsible Use

NetScope is intended for educational and authorized network-analysis environments.

Only capture or inspect traffic on systems and networks that you own or have explicit permission to analyze.

Payload preview is disabled by default and is limited to a short, truncated representation when enabled. The application does not attempt to decrypt encrypted traffic or recover passwords, authentication tokens, or credentials.

🚀 Getting Started

```bash
python -m venv .venv
