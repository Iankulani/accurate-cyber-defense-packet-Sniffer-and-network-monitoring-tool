import sys
import os
import time
import datetime
import socket
import threading
import subprocess
import json
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import queue
import platform
import dpkt
import netifaces
import dns.resolver
import speedtest
import psutil

# Constants
VERSION = "1.0.0"
BLUE_THEME = {
    'bg': '#1e3c72',
    'fg': 'white',
    'button_bg': '#2a5298',
    'button_active': '#1e3c72',
    'text_bg': '#0f2027',
    'highlight': '#4b79cf'
}

# Global variables
packet_queue = queue.Queue()
capture_thread = None
stop_capture = False
captured_packets = []
network_stats = defaultdict(int)
threat_alerts = []
interface = None
packet_count = 0
start_time = None
saved_packets = []

class NetworkMonitor:
    def __init__(self, master):
        self.master = master
        master.title(f"Accurate Cyber Defense Packet sniffer v{VERSION}")
        master.geometry("1200x800")
        master.configure(bg=BLUE_THEME['bg'])
        
        self.setup_ui()
        self.setup_menu()
        self.setup_terminal()
        self.setup_packet_display()
        self.setup_stats_panels()
        
        # Initialize network interface
        self.interfaces = self.get_network_interfaces()
        self.selected_interface = self.interfaces[0] if self.interfaces else None
        
        # Start background tasks
        self.start_background_tasks()
    
    def setup_ui(self):
        # Main frames
        self.left_frame = tk.Frame(self.master, bg=BLUE_THEME['bg'], width=300)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        self.right_frame = tk.Frame(self.master, bg=BLUE_THEME['bg'])
        self.right_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        # Left panel controls
        self.control_frame = tk.LabelFrame(self.left_frame, text="Controls", bg=BLUE_THEME['bg'], 
                                          fg=BLUE_THEME['fg'], padx=5, pady=5)
        self.control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Interface selection
        tk.Label(self.control_frame, text="Network Interface:", bg=BLUE_THEME['bg'], fg=BLUE_THEME['fg']).pack(anchor=tk.W)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(self.control_frame, textvariable=self.interface_var)
        self.interface_dropdown.pack(fill=tk.X, padx=5, pady=2)
        self.interface_dropdown['values'] = self.get_network_interfaces()
        if self.interface_dropdown['values']:
            self.interface_dropdown.current(0)
        
        # Target IP
        tk.Label(self.control_frame, text="Target IP:", bg=BLUE_THEME['bg'], fg=BLUE_THEME['fg']).pack(anchor=tk.W)
        self.target_ip_entry = tk.Entry(self.control_frame)
        self.target_ip_entry.pack(fill=tk.X, padx=5, pady=2)
        self.target_ip_entry.insert(0, "192.168.1.1")
        
        # Control buttons
        self.start_btn = tk.Button(self.control_frame, text="Start Monitoring", command=self.start_monitoring,
                                 bg=BLUE_THEME['button_bg'], fg=BLUE_THEME['fg'], activebackground=BLUE_THEME['button_active'])
        self.start_btn.pack(fill=tk.X, padx=5, pady=2)
        
        self.stop_btn = tk.Button(self.control_frame, text="Stop Monitoring", command=self.stop_monitoring,
                                bg=BLUE_THEME['button_bg'], fg=BLUE_THEME['fg'], activebackground=BLUE_THEME['button_active'],
                                state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, padx=5, pady=2)
        
        self.capture_btn = tk.Button(self.control_frame, text="Capture Packets", command=self.start_capture,
                                   bg=BLUE_THEME['button_bg'], fg=BLUE_THEME['fg'], activebackground=BLUE_THEME['button_active'])
        self.capture_btn.pack(fill=tk.X, padx=5, pady=2)
        
        self.view_btn = tk.Button(self.control_frame, text="View Packets", command=self.view_packets,
                                bg=BLUE_THEME['button_bg'], fg=BLUE_THEME['fg'], activebackground=BLUE_THEME['button_active'])
        self.view_btn.pack(fill=tk.X, padx=5, pady=2)
        
        self.export_btn = tk.Button(self.control_frame, text="Export Packets", command=self.export_packets,
                                   bg=BLUE_THEME['button_bg'], fg=BLUE_THEME['fg'], activebackground=BLUE_THEME['button_active'])
        self.export_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Stats panel
        self.stats_frame = tk.LabelFrame(self.left_frame, text="Statistics", bg=BLUE_THEME['bg'], 
                                       fg=BLUE_THEME['fg'], padx=5, pady=5)
        self.stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(self.stats_frame, height=10, bg=BLUE_THEME['text_bg'], 
                                                  fg=BLUE_THEME['fg'])
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        self.stats_text.insert(tk.END, "Network statistics will appear here...\n")
        self.stats_text.config(state=tk.DISABLED)
    
    def setup_menu(self):
        menubar = tk.Menu(self.master)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Packets", command=self.export_packets)
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping", command=self.show_ping_dialog)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute_dialog)
        tools_menu.add_command(label="DNS Lookup", command=self.show_dns_dialog)
        tools_menu.add_command(label="Port Scan", command=self.show_portscan_dialog)
        tools_menu.add_command(label="Bandwidth Test", command=self.run_bandwidth_test)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Protocol Distribution", command=self.show_protocol_chart)
        view_menu.add_command(label="Threat Analysis", command=self.show_threat_chart)
        view_menu.add_command(label="Bandwidth Usage", command=self.show_bandwidth_chart)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.master.config(menu=menubar)
    
    def setup_terminal(self):
        self.terminal_frame = tk.LabelFrame(self.right_frame, text="Terminal", bg=BLUE_THEME['bg'], 
                                          fg=BLUE_THEME['fg'], padx=5, pady=5)
        self.terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_text = scrolledtext.ScrolledText(self.terminal_frame, height=10, bg=BLUE_THEME['text_bg'], 
                                                      fg=BLUE_THEME['fg'])
        self.terminal_text.pack(fill=tk.BOTH, expand=True)
        self.terminal_text.insert(tk.END, "Cyber Security Monitoring Tool - Terminal\n")
        self.terminal_text.insert(tk.END, "Type 'help' for available commands\n")
        self.terminal_text.insert(tk.END, ">>> ")
        self.terminal_text.mark_set("input", tk.END)
        self.terminal_text.config(state=tk.NORMAL)
        
        self.command_entry = tk.Entry(self.terminal_frame, bg=BLUE_THEME['text_bg'], fg=BLUE_THEME['fg'])
        self.command_entry.pack(fill=tk.X, padx=5, pady=5)
        self.command_entry.bind("<Return>", self.process_command)
        self.command_entry.focus()
    
    def setup_packet_display(self):
        self.packet_frame = tk.LabelFrame(self.right_frame, text="Packet Details", bg=BLUE_THEME['bg'], 
                                        fg=BLUE_THEME['fg'], padx=5, pady=5)
        self.packet_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.packet_tree = ttk.Treeview(self.packet_frame, columns=("No", "Time", "Source", "Destination", "Protocol", "Length", "Info"))
        self.packet_tree.heading("#0", text="")
        self.packet_tree.heading("No", text="No")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Length", text="Length")
        self.packet_tree.heading("Info", text="Info")
        
        self.packet_tree.column("#0", width=0, stretch=tk.NO)
        self.packet_tree.column("No", width=50, anchor=tk.CENTER)
        self.packet_tree.column("Time", width=120, anchor=tk.CENTER)
        self.packet_tree.column("Source", width=150, anchor=tk.CENTER)
        self.packet_tree.column("Destination", width=150, anchor=tk.CENTER)
        self.packet_tree.column("Protocol", width=80, anchor=tk.CENTER)
        self.packet_tree.column("Length", width=80, anchor=tk.CENTER)
        self.packet_tree.column("Info", width=300, anchor=tk.W)
        
        vsb = ttk.Scrollbar(self.packet_frame, orient="vertical", command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(self.packet_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.packet_tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)
        
        self.packet_frame.grid_rowconfigure(0, weight=1)
        self.packet_frame.grid_columnconfigure(0, weight=1)
        
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
    
    def setup_stats_panels(self):
        self.threat_frame = tk.LabelFrame(self.right_frame, text="Threat Alerts", bg=BLUE_THEME['bg'], 
                                         fg=BLUE_THEME['fg'], padx=5, pady=5)
        self.threat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threat_text = scrolledtext.ScrolledText(self.threat_frame, height=5, bg=BLUE_THEME['text_bg'], 
                                                   fg='red')
        self.threat_text.pack(fill=tk.BOTH, expand=True)
        self.threat_text.insert(tk.END, "No threats detected...\n")
        self.threat_text.config(state=tk.DISABLED)
    
    def start_background_tasks(self):
        # Start packet processing thread
        self.packet_processor = threading.Thread(target=self.process_packets, daemon=True)
        self.packet_processor.start()
        
        # Start stats updater
        self.update_stats()
    
    def get_network_interfaces(self):
        interfaces = []
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(["netsh", "interface", "show", "interface"]).decode('utf-8')
                lines = output.split('\n')
                for line in lines[3:]:
                    if "Connected" in line:
                        parts = line.split()
                        interfaces.append(parts[-1])
            else:
                interfaces = netifaces.interfaces()
        except:
            interfaces = ["eth0", "wlan0", "lo"]  # Fallback
            
        return interfaces if interfaces else ["No interfaces found"]
    
    def start_monitoring(self):
        target_ip = self.target_ip_entry.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        self.terminal_print(f"Starting network monitoring for {target_ip}...")
        global stop_capture, capture_thread, interface
        
        interface = self.interface_var.get()
        stop_capture = False
        
        capture_thread = threading.Thread(target=self.capture_packets, args=(interface, target_ip), daemon=True)
        capture_thread.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.capture_btn.config(state=tk.DISABLED)
    
    def stop_monitoring(self):
        global stop_capture
        stop_capture = True
        
        if capture_thread and capture_thread.is_alive():
            capture_thread.join(timeout=1)
        
        self.terminal_print("Network monitoring stopped")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.capture_btn.config(state=tk.NORMAL)
    
    def start_capture(self):
        self.terminal_print("Starting packet capture...")
        global captured_packets, packet_count
        captured_packets = []
        packet_count = 0
        self.packet_tree.delete(*self.packet_tree.get_children())
    
    def capture_packets(self, interface, target_ip):
        try:
            # Use pcapy for efficient packet capture
            pc = pcapy.open_live(interface, 65536, True, 100)
            
            # Set filter for target IP
            filter = f"host {target_ip}"
            pc.setfilter(filter)
            
            self.terminal_print(f"Capturing packets on {interface} for {target_ip}...")
            
            while not stop_capture:
                (header, packet) = pc.next()
                if header:
                    packet_queue.put((header, packet))
            
        except Exception as e:
            self.terminal_print(f"Error capturing packets: {str(e)}")
    
    def process_packets(self):
        while True:
            if not packet_queue.empty():
                header, packet = packet_queue.get()
                self.process_packet(header, packet)
            time.sleep(0.01)
    
    def process_packet(self, header, packet_data):
        global packet_count, captured_packets, network_stats
        
        try:
            packet = dpkt.ethernet.Ethernet(packet_data)
            if not isinstance(packet.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return
                
            ip = packet.data
            protocol = ip.p
            src_ip = socket.inet_ntoa(ip.src) if hasattr(ip, 'src') else "N/A"
            dst_ip = socket.inet_ntoa(ip.dst) if hasattr(ip, 'dst') else "N/A"
            
            # Get current time
            timestamp = datetime.datetime.fromtimestamp(header.getts()[0]).strftime('%H:%M:%S.%f')
            
            # Protocol analysis
            protocol_name = self.get_protocol_name(protocol)
            network_stats[protocol_name] += 1
            
            # Packet info
            info = ""
            length = header.getlen()
            
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                info = f"TCP {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport} Flags: {self.get_tcp_flags(tcp.flags)}"
                
                # Detect potential threats
                self.detect_threats(ip, tcp, None)
                
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                info = f"UDP {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport} Length: {udp.ulen}"
                
                # Detect potential threats
                self.detect_threats(ip, None, udp)
            
            # Add to captured packets
            packet_count += 1
            packet_info = {
                'no': packet_count,
                'time': timestamp,
                'src': src_ip,
                'dst': dst_ip,
                'protocol': protocol_name,
                'length': length,
                'info': info,
                'raw': packet_data
            }
            
            captured_packets.append(packet_info)
            saved_packets.append(packet_info)
            
            # Update UI
            self.master.after(0, self.update_packet_list, packet_info)
            
        except Exception as e:
            self.terminal_print(f"Error processing packet: {str(e)}")
    
    def get_protocol_name(self, protocol_num):
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            58: "ICMPv6"
        }
        return protocols.get(protocol_num, f"Unknown ({protocol_num})")
    
    def get_tcp_flags(self, flags):
        flag_names = []
        if flags & dpkt.tcp.TH_FIN: flag_names.append("FIN")
        if flags & dpkt.tcp.TH_SYN: flag_names.append("SYN")
        if flags & dpkt.tcp.TH_RST: flag_names.append("RST")
        if flags & dpkt.tcp.TH_PUSH: flag_names.append("PSH")
        if flags & dpkt.tcp.TH_ACK: flag_names.append("ACK")
        if flags & dpkt.tcp.TH_URG: flag_names.append("URG")
        if flags & dpkt.tcp.TH_ECE: flag_names.append("ECE")
        if flags & dpkt.tcp.TH_CWR: flag_names.append("CWR")
        return "/".join(flag_names) if flag_names else "None"
    
    def detect_threats(self, ip, tcp, udp):
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        # Detect port scanning
        if tcp and (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
            self.add_threat_alert(f"Potential port scan detected from {src_ip}")
        
        # Detect SYN flood (DoS)
        syn_count = sum(1 for p in captured_packets[-100:] 
                       if p['protocol'] == 'TCP' and 'SYN' in p['info'] and not 'ACK' in p['info'])
        if syn_count > 50:
            self.add_threat_alert(f"Potential SYN flood (DoS) attack detected from {src_ip}")
        
        # Detect UDP flood (DDoS)
        udp_count = sum(1 for p in captured_packets[-100:] if p['protocol'] == 'UDP')
        if udp_count > 100:
            self.add_threat_alert(f"Potential UDP flood (DDoS) attack detected from {src_ip}")
    
    def add_threat_alert(self, message):
        global threat_alerts
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        alert = f"[{timestamp}] {message}"
        
        if alert not in threat_alerts:
            threat_alerts.append(alert)
            self.master.after(0, self.update_threat_display)
    
    def update_packet_list(self, packet_info):
        self.packet_tree.insert("", tk.END, values=(
            packet_info['no'],
            packet_info['time'],
            packet_info['src'],
            packet_info['dst'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info']
        ))
        
        # Auto-scroll to the end
        self.packet_tree.yview_moveto(1)
    
    def update_threat_display(self):
        self.threat_text.config(state=tk.NORMAL)
        self.threat_text.delete(1.0, tk.END)
        
        for alert in threat_alerts[-10:]:  # Show last 10 alerts
            self.threat_text.insert(tk.END, alert + "\n")
        
        self.threat_text.config(state=tk.DISABLED)
        self.threat_text.yview_moveto(1)
    
    def update_stats(self):
        # Update network statistics
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        # Protocol distribution
        self.stats_text.insert(tk.END, "Protocol Distribution:\n")
        total = sum(network_stats.values())
        for proto, count in network_stats.items():
            percent = (count / total * 100) if total > 0 else 0
            self.stats_text.insert(tk.END, f"  {proto}: {count} ({percent:.1f}%)\n")
        
        # Packet count
        self.stats_text.insert(tk.END, f"\nTotal Packets: {packet_count}\n")
        
        # Bandwidth usage
        net_io = psutil.net_io_counters()
        self.stats_text.insert(tk.END, "\nBandwidth Usage:\n")
        self.stats_text.insert(tk.END, f"  Bytes Sent: {net_io.bytes_sent / 1024:.1f} KB\n")
        self.stats_text.insert(tk.END, f"  Bytes Received: {net_io.bytes_recv / 1024:.1f} KB\n")
        
        self.stats_text.config(state=tk.DISABLED)
        
        # Schedule next update
        self.master.after(2000, self.update_stats)
    
    def view_packets(self):
        if not captured_packets:
            messagebox.showinfo("Info", "No packets captured yet")
            return
        
        self.terminal_print(f"Viewing {len(captured_packets)} captured packets")
    
    def export_packets(self):
        if not captured_packets:
            messagebox.showinfo("Info", "No packets to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Create a pcap writer
                with open(file_path, 'wb') as f:
                    pcap_writer = dpkt.pcap.Writer(f)
                    
                    for packet_info in captured_packets:
                        pcap_writer.writepkt(packet_info['raw'])
                
                self.terminal_print(f"Packets exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export packets: {str(e)}")
    
    def show_packet_details(self, event):
        item = self.packet_tree.selection()[0]
        packet_no = self.packet_tree.item(item, 'values')[0]
        
        packet = next((p for p in captured_packets if p['no'] == int(packet_no)), None)
        if packet:
            self.show_packet_dialog(packet)
    
    def show_packet_dialog(self, packet):
        dialog = tk.Toplevel(self.master)
        dialog.title(f"Packet Details #{packet['no']}")
        dialog.geometry("800x600")
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        
        # Basic info
        text.insert(tk.END, f"Packet #{packet['no']}\n")
        text.insert(tk.END, f"Time: {packet['time']}\n")
        text.insert(tk.END, f"Source: {packet['src']}\n")
        text.insert(tk.END, f"Destination: {packet['dst']}\n")
        text.insert(tk.END, f"Protocol: {packet['protocol']}\n")
        text.insert(tk.END, f"Length: {packet['length']} bytes\n\n")
        
        # Hex dump
        text.insert(tk.END, "Hex Dump:\n")
        hex_dump = ' '.join(f'{b:02x}' for b in packet['raw'][:64])
        if len(packet['raw']) > 64:
            hex_dump += " ..."
        text.insert(tk.END, hex_dump + "\n")
        
        text.config(state=tk.DISABLED)
    
    def process_command(self, event):
        command = self.command_entry.get()
        self.command_entry.delete(0, tk.END)
        
        self.terminal_print(f">>> {command}")
        
        # Process command
        parts = command.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "help":
            self.show_help()
        elif cmd == "ping":
            self.do_ping(args)
        elif cmd == "traceroute":
            self.do_traceroute(args)
        elif cmd == "ifconfig":
            self.do_ifconfig()
        elif cmd == "start":
            if "monitoring" in command.lower():
                self.start_monitoring()
            else:
                self.terminal_print("Unknown command. Try 'start monitoring'")
        elif cmd == "capture":
            self.start_capture()
        elif cmd == "stop":
            self.stop_monitoring()
        elif cmd == "view":
            self.view_packets()
        elif cmd == "export":
            self.export_packets()
        elif cmd == "exit":
            self.master.quit()
        elif cmd == "nslookup" or cmd == "dns":
            self.do_dns_lookup(args)
        elif cmd == "clear":
            self.terminal_text.config(state=tk.NORMAL)
            self.terminal_text.delete(1.0, tk.END)
            self.terminal_text.insert(tk.END, ">>> ")
            self.terminal_text.config(state=tk.NORMAL)
        else:
            self.terminal_print(f"Unknown command: {cmd}. Type 'help' for available commands.")
    
    def terminal_print(self, message):
        self.terminal_text.config(state=tk.NORMAL)
        self.terminal_text.insert(tk.END, message + "\n")
        self.terminal_text.insert(tk.END, ">>> ")
        self.terminal_text.see(tk.END)
        self.terminal_text.config(state=tk.NORMAL)
    
    def show_help(self):
        help_text = """Available Commands:
  help                      - Show this help message
  ping <ip/hostname>        - Ping a host
  traceroute <ip/hostname>  - Trace route to a host
  ifconfig                  - Show network interfaces
  start monitoring          - Start network monitoring
  capture                   - Start packet capture
  stop                      - Stop monitoring
  view                      - View captured packets
  export                    - Export captured packets
  nslookup <hostname>       - DNS lookup
  clear                     - Clear terminal
  exit                      - Exit the program
"""
        self.terminal_print(help_text)
    
    def do_ping(self, args):
        if not args:
            self.terminal_print("Usage: ping <ip/hostname>")
            return
        
        target = args[0]
        self.terminal_print(f"Pinging {target}...")
        
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["ping", "-n", "4", target], stderr=subprocess.STDOUT)
            else:
                output = subprocess.check_output(["ping", "-c", "4", target], stderr=subprocess.STDOUT)
            
            self.terminal_print(output.decode('utf-8'))
        except subprocess.CalledProcessError as e:
            self.terminal_print(f"Ping failed: {e.output.decode('utf-8')}")
    
    def do_traceroute(self, args):
        if not args:
            self.terminal_print("Usage: traceroute <ip/hostname>")
            return
        
        target = args[0]
        self.terminal_print(f"Tracing route to {target}...")
        
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["tracert", target], stderr=subprocess.STDOUT)
            else:
                output = subprocess.check_output(["traceroute", target], stderr=subprocess.STDOUT)
            
            self.terminal_print(output.decode('utf-8'))
        except subprocess.CalledProcessError as e:
            self.terminal_print(f"Traceroute failed: {e.output.decode('utf-8')}")
    
    def do_ifconfig(self):
        self.terminal_print("Network Interfaces:")
        
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["ipconfig", "/all"], stderr=subprocess.STDOUT)
            else:
                output = subprocess.check_output(["ifconfig", "-a"], stderr=subprocess.STDOUT)
            
            self.terminal_print(output.decode('utf-8'))
        except subprocess.CalledProcessError as e:
            self.terminal_print(f"Failed to get interface info: {e.output.decode('utf-8')}")
    
    def do_dns_lookup(self, args):
        if not args:
            self.terminal_print("Usage: nslookup <hostname>")
            return
        
        hostname = args[0]
        self.terminal_print(f"Looking up {hostname}...")
        
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            for rdata in answers:
                self.terminal_print(f"{hostname} has address {rdata.address}")
        except Exception as e:
            self.terminal_print(f"DNS lookup failed: {str(e)}")
    
    def show_ping_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Ping Tool")
        dialog.geometry("400x200")
        
        tk.Label(dialog, text="Enter host to ping:").pack(pady=10)
        
        entry = tk.Entry(dialog, width=30)
        entry.pack(pady=5)
        entry.focus()
        
        output = scrolledtext.ScrolledText(dialog, height=8)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def do_ping():
            host = entry.get()
            if not host:
                return
            
            output.config(state=tk.NORMAL)
            output.insert(tk.END, f"Pinging {host}...\n")
            output.see(tk.END)
            
            try:
                if platform.system().lower() == "windows":
                    process = subprocess.Popen(["ping", "-n", "4", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    process = subprocess.Popen(["ping", "-c", "4", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    output.insert(tk.END, line.decode('utf-8'))
                    output.see(tk.END)
                    output.update_idletasks()
                
                process.wait()
            except Exception as e:
                output.insert(tk.END, f"Error: {str(e)}\n")
            
            output.config(state=tk.DISABLED)
        
        tk.Button(dialog, text="Ping", command=do_ping).pack(pady=5)
    
    def show_traceroute_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Traceroute Tool")
        dialog.geometry("500x300")
        
        tk.Label(dialog, text="Enter host to trace:").pack(pady=10)
        
        entry = tk.Entry(dialog, width=30)
        entry.pack(pady=5)
        entry.focus()
        
        output = scrolledtext.ScrolledText(dialog, height=12)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def do_trace():
            host = entry.get()
            if not host:
                return
            
            output.config(state=tk.NORMAL)
            output.insert(tk.END, f"Tracing route to {host}...\n")
            output.see(tk.END)
            
            try:
                if platform.system().lower() == "windows":
                    process = subprocess.Popen(["tracert", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    process = subprocess.Popen(["traceroute", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    output.insert(tk.END, line.decode('utf-8'))
                    output.see(tk.END)
                    output.update_idletasks()
                
                process.wait()
            except Exception as e:
                output.insert(tk.END, f"Error: {str(e)}\n")
            
            output.config(state=tk.DISABLED)
        
        tk.Button(dialog, text="Trace", command=do_trace).pack(pady=5)
    
    def show_dns_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("DNS Lookup Tool")
        dialog.geometry("500x300")
        
        tk.Label(dialog, text="Enter hostname to lookup:").pack(pady=10)
        
        entry = tk.Entry(dialog, width=30)
        entry.pack(pady=5)
        entry.focus()
        
        output = scrolledtext.ScrolledText(dialog, height=12)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def do_lookup():
            hostname = entry.get()
            if not hostname:
                return
            
            output.config(state=tk.NORMAL)
            output.insert(tk.END, f"Looking up {hostname}...\n")
            output.see(tk.END)
            
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                for rdata in answers:
                    output.insert(tk.END, f"{hostname} has address {rdata.address}\n")
                
                # Try MX records
                try:
                    mx_answers = dns.resolver.resolve(hostname, 'MX')
                    output.insert(tk.END, "\nMail Exchange (MX) records:\n")
                    for rdata in mx_answers:
                        output.insert(tk.END, f"{rdata.preference} {rdata.exchange}\n")
                except:
                    pass
                
                output.see(tk.END)
            except Exception as e:
                output.insert(tk.END, f"DNS lookup failed: {str(e)}\n")
            
            output.config(state=tk.DISABLED)
        
        tk.Button(dialog, text="Lookup", command=do_lookup).pack(pady=5)
    
    def show_portscan_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Port Scanner")
        dialog.geometry("500x400")
        
        tk.Label(dialog, text="Enter target IP:").pack(pady=5)
        
        ip_entry = tk.Entry(dialog, width=30)
        ip_entry.pack(pady=5)
        ip_entry.insert(0, "127.0.0.1")
        
        tk.Label(dialog, text="Port range (start-end):").pack(pady=5)
        
        port_frame = tk.Frame(dialog)
        port_frame.pack(pady=5)
        
        start_entry = tk.Entry(port_frame, width=8)
        start_entry.pack(side=tk.LEFT)
        start_entry.insert(0, "1")
        
        tk.Label(port_frame, text="to").pack(side=tk.LEFT, padx=5)
        
        end_entry = tk.Entry(port_frame, width=8)
        end_entry.pack(side=tk.LEFT)
        end_entry.insert(0, "100")
        
        output = scrolledtext.ScrolledText(dialog, height=15)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def scan_ports():
            target = ip_entry.get()
            if not target:
                return
            
            try:
                start_port = int(start_entry.get())
                end_port = int(end_entry.get())
                
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    output.insert(tk.END, "Invalid port range\n")
                    return
            except ValueError:
                output.insert(tk.END, "Invalid port numbers\n")
                return
            
            output.config(state=tk.NORMAL)
            output.delete(1.0, tk.END)
            output.insert(tk.END, f"Scanning ports {start_port}-{end_port} on {target}...\n")
            output.see(tk.END)
            output.update_idletasks()
            
            open_ports = []
            
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                        output.insert(tk.END, f"Port {port} is open\n")
                        output.see(tk.END)
                        output.update_idletasks()
                except:
                    pass
            
            # Use threading to speed up scanning
            threads = []
            for port in range(start_port, end_port + 1):
                t = threading.Thread(target=check_port, args=(port,))
                threads.append(t)
                t.start()
                
                # Limit number of concurrent threads
                if len(threads) >= 50:
                    for t in threads:
                        t.join()
                    threads = []
            
            # Wait for remaining threads
            for t in threads:
                t.join()
            
            if open_ports:
                output.insert(tk.END, f"\nScan complete. Open ports: {', '.join(map(str, open_ports))}\n")
            else:
                output.insert(tk.END, "\nScan complete. No open ports found in the specified range.\n")
            
            output.config(state=tk.DISABLED)
        
        tk.Button(dialog, text="Scan Ports", command=scan_ports).pack(pady=5)
    
    def run_bandwidth_test(self):
        self.terminal_print("Running bandwidth test... This may take a moment.")
        
        def run_test():
            try:
                st = speedtest.Speedtest()
                st.get_best_server()
                
                self.terminal_print("Testing download speed...")
                download_speed = st.download() / 1_000_000  # Convert to Mbps
                
                self.terminal_print("Testing upload speed...")
                upload_speed = st.upload() / 1_000_000  # Convert to Mbps
                
                self.terminal_print("\nSpeed Test Results:")
                self.terminal_print(f"Download: {download_speed:.2f} Mbps")
                self.terminal_print(f"Upload: {upload_speed:.2f} Mbps")
                
                # Show in a chart
                self.show_bandwidth_chart(download_speed, upload_speed)
            except Exception as e:
                self.terminal_print(f"Bandwidth test failed: {str(e)}")
        
        # Run in a thread to avoid freezing the UI
        threading.Thread(target=run_test, daemon=True).start()
    
    def show_protocol_chart(self):
        if not network_stats:
            messagebox.showinfo("Info", "No protocol data available yet")
            return
        
        # Create a pie chart
        fig, ax = plt.subplots(figsize=(6, 4))
        protocols = list(network_stats.keys())
        counts = list(network_stats.values())
        
        ax.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')  # Equal aspect ratio ensures pie is drawn as a circle
        ax.set_title("Protocol Distribution")
        
        # Display in a new window
        self.display_chart(fig)
    
    def show_threat_chart(self):
        if not threat_alerts:
            messagebox.showinfo("Info", "No threats detected yet")
            return
        
        # Count threat types
        threat_counts = defaultdict(int)
        for alert in threat_alerts:
            if "port scan" in alert.lower():
                threat_counts["Port Scan"] += 1
            elif "syn flood" in alert.lower():
                threat_counts["SYN Flood"] += 1
            elif "udp flood" in alert.lower():
                threat_counts["UDP Flood"] += 1
            else:
                threat_counts["Other"] += 1
        
        # Create a bar chart
        fig, ax = plt.subplots(figsize=(6, 4))
        threats = list(threat_counts.keys())
        counts = list(threat_counts.values())
        
        ax.bar(threats, counts, color=['red', 'orange', 'yellow', 'purple'])
        ax.set_title("Threat Analysis")
        ax.set_ylabel("Count")
        
        # Display in a new window
        self.display_chart(fig)
    
    def show_bandwidth_chart(self, download=None, upload=None):
        # Create a bar chart
        fig, ax = plt.subplots(figsize=(6, 4))
        
        if download is not None and upload is not None:
            # Show specific values
            labels = ['Download', 'Upload']
            speeds = [download, upload]
            ax.bar(labels, speeds, color=['blue', 'green'])
            ax.set_title(f"Bandwidth Test\nDownload: {download:.2f} Mbps, Upload: {upload:.2f} Mbps")
            ax.set_ylabel("Speed (Mbps)")
        else:
            # Show general usage
            net_io = psutil.net_io_counters()
            labels = ['Bytes Sent', 'Bytes Received']
            bytes_data = [net_io.bytes_sent / 1024, net_io.bytes_recv / 1024]  # Convert to KB
            ax.bar(labels, bytes_data, color=['blue', 'green'])
            ax.set_title("Bandwidth Usage")
            ax.set_ylabel("Kilobytes")
        
        # Display in a new window
        self.display_chart(fig)
    
    def display_chart(self, fig):
        chart_window = tk.Toplevel(self.master)
        chart_window.title("Chart View")
        
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        toolbar = tk.Frame(chart_window)
        toolbar.pack(fill=tk.X)
        
        def save_chart():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
            )
            if file_path:
                fig.savefig(file_path)
                self.terminal_print(f"Chart saved to {file_path}")
        
        tk.Button(toolbar, text="Save Chart", command=save_chart).pack(side=tk.RIGHT, padx=5, pady=5)
    
    def show_about(self):
        about_text = f"""Accurate Cyber Defense | Packet Sniffer and Monitoring Tool v{VERSION}


Author:Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
phone+265988061969

A comprehensive network security tool for:
- Packet capturing and analysis
- Network monitoring
- Threat detection
- Bandwidth monitoring
- Network troubleshooting

Features:
- Real-time packet capture
- Threat detection (port scans, DoS, DDoS)
- Protocol analysis
- Bandwidth testing
- DNS lookup tools
- Port scanning
- Data visualization
"""
        messagebox.showinfo("About", about_text)

def main():
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()