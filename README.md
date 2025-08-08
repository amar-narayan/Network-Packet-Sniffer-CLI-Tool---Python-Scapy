# 🕵️‍♂️ Network Packet Sniffer (CLI Tool) - Python + Scapy

## 📌 Overview
This is a **command-line packet sniffer** built in **Python** using the **Scapy** library.  
It captures live TCP/IP network traffic, analyzes it, applies filters, and logs the results for further inspection.

The tool can:
- Capture **real-time packets**
- Filter by **protocol type** (TCP, UDP, ICMP)
- Filter by **IP address**
- Detect **suspicious patterns** in payloads (basic intrusion detection)
- Save captured data to a log file

---

## 🎯 Features
- **Live Packet Capture** – Sniffs packets in real-time from the selected network interface.
- **Protocol Filtering** – Focus on TCP, UDP, ICMP, or all traffic.
- **IP Filtering** – Capture only packets from/to specific IP addresses.
- **Suspicious Pattern Detection** – Flags payloads matching common attack signatures.
- **Logging** – Saves all captured packet details to a file for later analysis.
- **Verbose Mode** – Shows packet payloads for deeper inspection.

---

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/amar-narayan/packet-sniffer.git
cd packet-sniffer
