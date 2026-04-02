import time
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP

class FlowTracker:
    def __init__(self, timeout=10.0, min_packets=5):
        self.flows = {}
        self.timeout = timeout
        self.min_packets = min_packets  # Minimum packets to trigger ML

    def update(self, scapy_pkt):
        if not scapy_pkt.haslayer(IP):
            return None

        src_ip = scapy_pkt[IP].src
        dst_ip = scapy_pkt[IP].dst
        proto = scapy_pkt[IP].proto
        size = len(scapy_pkt)
        now = time.time()

        src_port = 0
        dst_port = 0
        is_syn = is_ack = is_fin = False
        
        if scapy_pkt.haslayer(TCP):
            src_port = scapy_pkt[TCP].sport
            dst_port = scapy_pkt[TCP].dport
            flags = scapy_pkt[TCP].flags
            is_syn = 'S' in flags
            is_ack = 'A' in flags
            is_fin = 'F' in flags
        elif scapy_pkt.haslayer(UDP):
            src_port = scapy_pkt[UDP].sport
            dst_port = scapy_pkt[UDP].dport

        # Flow key: 5-tuple
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'start_time': now,
                'last_time': now,
                'packet_count': 0,
                'total_bytes': 0,
                'iats': [],
                'syn_count': 0,
                'ack_count': 0,
                'fin_count': 0,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'proto': proto
            }

        f = self.flows[flow_key]
        f['packet_count'] += 1
        f['total_bytes'] += size
        if f['packet_count'] > 1:
            f['iats'].append(now - f['last_time'])
        f['last_time'] = now
        if is_syn: f['syn_count'] += 1
        if is_ack: f['ack_count'] += 1
        if is_fin: f['fin_count'] += 1

        return f

    def get_features(self, flow):
        duration = max(flow['last_time'] - flow['start_time'], 1e-6)
        pkts = flow['packet_count']
        
        # New features as requested:
        iats = flow['iats']
        iat_mean = np.mean(iats) if iats else 0
        iat_std = np.std(iats) if len(iats) > 1 else 0
        
        syn_ratio = flow['syn_count'] / pkts
        ack_ratio = flow['ack_count'] / pkts
        fin_ratio = flow['fin_count'] / pkts
        
        # Burst rate detection (packets in last second)
        # Simplified: if duration > 1, use moving average
        packet_rate = pkts / duration
        byte_rate = flow['total_bytes'] / duration
        
        features = {
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'duration': duration,
            'iat_mean': iat_mean,
            'iat_std': iat_std,
            'syn_ratio': syn_ratio,
            'ack_ratio': ack_ratio,
            'fin_ratio': fin_ratio,
            'avg_packet_size': flow['total_bytes'] / pkts
        }
        return features

    def clear_expired(self):
        now = time.time()
        expired = [k for k, f in self.flows.items() if now - f['last_time'] > self.timeout]
        for k in expired:
            del self.flows[k]
