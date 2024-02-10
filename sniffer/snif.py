import os
import scapy.all as scapy
import pandas as pd
from scapy.all import rdpcap, IP, TCP
from collections import deque
from numpy import std, mean, var

MAX_BUFFER_SIZE = 3
BUFFER = deque()
PCAP_FOLDER = 'pcap_buffer'
TEXT_FOLDER = 'text_buffer'
CSV_FILE = 'output.csv'

def packet_handler(packet):
    global BUFFER
    BUFFER.append(packet)
    
    if len(BUFFER) >= MAX_BUFFER_SIZE:
        process_buffer()

def process_buffer():
    global BUFFER
    global PCAP_FOLDER
    global TEXT_FOLDER

    pcap_file = f"{PCAP_FOLDER}/buffer_{len(BUFFER)}.pcap"
    scapy.wrpcap(pcap_file, BUFFER)
    
    for i, packet in enumerate(BUFFER):
        features = extract_features(packet, BUFFER)
        text_file = f"{TEXT_FOLDER}/packet_{i + 1}_features.txt"
        with open(text_file, 'w') as file:
            file.write(str(features))
    
    BUFFER.clear()

def extract_features(packet, all_packets):
    features = {
        'Dst Port': packet[IP].dport if packet.haslayer(IP) and packet.haslayer(TCP) else 0,
        'Protocol': packet[IP].proto if packet.haslayer(IP) else 0,
        'Fwd Pkts/s': len(packet[TCP].payload) / float(packet.time - packet[TCP].payload.fields.get("time", packet.time)) if packet.haslayer(IP) and packet.haslayer(TCP) and 'time' in packet[TCP].payload.fields else 0,
        'Bwd Pkts/s': len(packet[TCP].payload) / float(packet[TCP].payload.fields.get("time", 1)) if packet.haslayer(IP) and packet.haslayer(TCP) and 'time' in packet[TCP].payload.fields else 0,
        'Bwd Pkt Len Min': min([len(pkt) for pkt in packet[TCP].payload]) if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].payload else 0,
        'Flow Byts/s': packet[TCP].info if TCP in packet and hasattr(packet[TCP], 'info') else 0,
        'Fwd IAT Tot': packet[TCP].time - packet[TCP].payload.fields.get("time", 0) if TCP in packet and 'time' in packet[TCP].payload.fields else 0,
        'Fwd IAT Mean': packet[TCP].payload.time / len(packet[TCP].payload) if TCP in packet and packet[TCP].payload else 0,
        'Fwd IAT Min': min([pkt.time for pkt in packet[TCP].payload]) if TCP in packet and packet[TCP].payload else 0,
        'Bwd IAT Tot': packet[TCP].payload.fields.get("time", 0) if TCP in packet and 'time' in packet[TCP].payload.fields else 0,
        'Bwd IAT Std': std([pkt.time for pkt in packet[TCP].payload]) if TCP in packet and packet[TCP].payload else 0,
        'Bwd IAT Max': max([pkt.time for pkt in packet[TCP].payload]) if TCP in packet and packet[TCP].payload else 0,
        'Bwd IAT Min': min([pkt.time for pkt in packet[TCP].payload]) if TCP in packet and packet[TCP].payload else 0,
        'Fwd PSH Flags': packet[TCP].flags.PSH if TCP in packet else 0,
        'Fwd URG Flags': packet[TCP].flags.URG if TCP in packet else 0,
        'Pkt Len Min': len(packet) if len(packet) > 0 else 0,
        'Pkt Len Std': std([len(pkt) for pkt in packet]) if len(packet) > 0 else 0,
        'Pkt Len Var': var([len(pkt) for pkt in packet]) if len(packet) > 0 else 0,
        'FIN Flag Cnt': packet[TCP].flags.FIN if TCP in packet and hasattr(packet[TCP].flags, 'FIN') else 0,
        'PSH Flag Cnt': packet[TCP].flags.PSH if TCP in packet and hasattr(packet[TCP].flags, 'PSH') else 0,
        'ACK Flag Cnt': packet[TCP].flags.ACK if TCP in packet and hasattr(packet[TCP].flags, 'ACK') else 0,
        'URG Flag Cnt': packet[TCP].flags.URG if TCP in packet and hasattr(packet[TCP].flags, 'URG') else 0,
        'ECE Flag Cnt': packet[TCP].flags.ECE if TCP in packet and hasattr(packet[TCP].flags, 'ECE') else 0,

        'Down/Up Ratio': len(packet[TCP].payload) / packet[TCP].payload.fields.get("ack", 1) if TCP in packet and 'ack' in packet[TCP].payload.fields else 0,
        'Fwd Seg Size Avg': mean([pkt[TCP].options[0][1] if TCP in pkt and pkt[TCP].options else 0 for pkt in all_packets]) if len(all_packets) > 0 else 0,
        'Bwd Seg Size Avg': mean([pkt[TCP].options[0][1] if TCP in pkt and pkt[TCP].options else 0 for pkt in all_packets]) if len(all_packets) > 0 else 0,
        'Subflow Bwd Byts': sum([len(pkt) for pkt in all_packets]) if len(all_packets) > 0 else 0,
        'Init Fwd Win Byts': packet[TCP].window if TCP in packet else 0,
        'Init Bwd Win Byts': packet[TCP].window if TCP in packet else 0,
        'Fwd Act Data Pkts': sum([1 for pkt in all_packets if TCP in pkt and pkt[TCP].flags.PSH]) if len(all_packets) > 0 else 0,
        'Fwd Seg Size Min': min([pkt[TCP].options[0][1] if TCP in pkt and pkt[TCP].options else 0 for pkt in all_packets]) if len(all_packets) > 0 else 0,
        'Active Max': max([packet.time for packet in all_packets]) if len(all_packets) > 0 else 0,
        'Active Min': min([packet.time for packet in all_packets]) if len(all_packets) > 0 else 0,
        'Active Std': std([float(packet.time) for packet in all_packets]) if len(all_packets) > 0 else 0,
        'Idle Std': std([float(packet.time) for packet in all_packets]) if len(all_packets) > 0 else 0,
        'Idle Min': min([packet.time for packet in all_packets]) if len(all_packets) > 0 else 0,
    }
    return features

def main():
    if not os.path.exists(PCAP_FOLDER):
        os.makedirs(PCAP_FOLDER)
    if not os.path.exists(TEXT_FOLDER):
        os.makedirs(TEXT_FOLDER)
    
    scapy.sniff(prn=packet_handler, store=0, count=100, timeout=10)

    if BUFFER:
        process_buffer()

    print(f"Packet capture and feature extraction completed. Check the '{CSV_FILE}' file.")

if _name_ == "_main_":
    main()