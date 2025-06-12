# accurate-cyber-defense-packet-Sniffer-and-network-monitoring-tool
accurate-cyber-defense-packet-sniffer-and-network-monitoring-tool is a powerful, modular, and educational cybersecurity solution designed to monitor, analyze, and report real-time network traffic and detect suspicious activity across enterprise or industrial control system (ICS)/SCADA networks.


This tool combines the capabilities of packet sniffing, protocol-based filtering, port scanning, and live charting to empower security analysts, students, and researchers with actionable insights. It is particularly suited for network defense simulations, cyber defense exercises, or lab-based learning environments.

Built in Python, this tool serves as an open-source foundation for learning how modern network surveillance, threat detection, and packet-level monitoring systems work.

🎯 Key Features
🧲 Real-time Packet Sniffing
Capture and decode IP packets from a live network interface or a static pcap file using scapy.

📊 Visual Analytics
Displays live histograms, pie charts, bar charts, and custom parabola graphs of traffic by protocol, port, and IP.

📡 Port Scanning & Service Detection
Perform targeted scans to detect open and closed ports using both TCP and UDP.

🕵️ Protocol Filtering
Supports selective capture and analysis of TCP, UDP, ICMP, HTTP, HTTPS, FTP, SSH, and DNS packets.

📁 Export Options
Export packet data to .csv, .json, or .txt for further offline analysis.

🔍 Deep Packet Inspection (DPI)
Drill down into packet headers and payload data for forensic and compliance checks.

📈 Real-Time Updating GUI
Custom-built GUI using Tkinter with white/blue themes, interactive filtering, and dynamic chart updates.

📥 Auto Save Feature
Automatically saves packet logs and charts at regular intervals to prevent data loss.

🔐 SCADA/ICS Awareness
Designed to simulate monitoring industrial protocols often used in SCADA networks for educational cybersecurity defense exercises.

🧰 Technologies Used
scapy: for packet capture and manipulation

socket: for low-level networking

matplotlib / seaborn: for visualization

Tkinter: for the GUI interface

threading: for non-blocking, real-time performance

json, csv: for data export

datetime: for timestamping packets and logs

os, sys, argparse: for cross-platform operation and command-line integration

💻 Use Cases
Scenario	Benefit
Cybersecurity education	Teaches students how packet sniffing and protocol analysis work.
Network troubleshooting	Identifies misconfigured or vulnerable network devices.
Threat research	Assists in recognizing anomalies or scanning activity from attackers.
ICS/SCADA defense testing	Models attacks on industrial control systems for training and response drills.
Capture the Flag (CTF)	Great for use in packet analysis challenges.

