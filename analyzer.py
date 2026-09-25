from collections import Counter
from datetime import datetime
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Raw
from config import settings
class PacketAnalyzer:
    def packet_records(self, packets, show_payload=False):
        return [self.packet_to_record(p, i, show_payload) for i, p in enumerate(list(packets)[:settings.max_packets], 1)]
    def packet_to_record(self, packet, number, show_payload=False):
        source, destination = "—", "—"
        protocol = self.protocol_name(packet)
        length = len(bytes(packet))
        info, layers = [], []
        if packet.haslayer(Ether):
            layers.append("Ethernet")
            info.append(f"EtherType={getattr(packet[Ether], 'type', '—')}")
        if packet.haslayer(IP):
            layers.append("IPv4")
            source, destination = packet[IP].src, packet[IP].dst
            info.append(f"TTL={packet[IP].ttl}")
        elif packet.haslayer(IPv6):
            layers.append("IPv6")
            source, destination = packet[IPv6].src, packet[IPv6].dst
        if packet.haslayer(TCP):
            layers.append("TCP")
            info.append(f"{packet[TCP].sport} → {packet[TCP].dport}; flags={packet[TCP].flags}")
        elif packet.haslayer(UDP):
            layers.append("UDP")
            info.append(f"{packet[UDP].sport} → {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            layers.append("ICMP")
            info.append(f"type={packet[ICMP].type}; code={packet[ICMP].code}")
        payload_preview = ""
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if show_payload:
                safe = payload[:settings.max_payload_preview]
                payload_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in safe)
                if len(payload) > settings.max_payload_preview:
                    payload_preview += "…"
            else:
                info.append(f"Raw payload bytes={len(payload)}")
        ts = getattr(packet, "time", None)
        try:
            timestamp = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "No.": number, "Time": timestamp, "Source": source, "Destination": destination,
            "Protocol": protocol, "Length": length, "Info": "; ".join(info),
            "Payload Preview": payload_preview, "layers": layers,
            "details": f"{source} → {destination} | {protocol} | {length} bytes | {'; '.join(info)}",
        }
    def protocol_name(self, packet):
        if packet.haslayer(TCP): return "TCP"
        if packet.haslayer(UDP): return "UDP"
        if packet.haslayer(ICMP): return "ICMP"
        if packet.haslayer(IP): return "IPv4"
        if packet.haslayer(IPv6): return "IPv6"
        if packet.haslayer(Ether): return "Ethernet"
        return packet.name if getattr(packet, "name", None) else "Other"
    def analyze(self, records):
        protocols = Counter(r["Protocol"] for r in records)
        endpoint_counts = Counter()
        for r in records:
            endpoint_counts[r["Source"]] += 1
            endpoint_counts[r["Destination"]] += 1
        top_endpoints = [{"Endpoint": e, "Observed references": c} for e, c in endpoint_counts.most_common(12)]
        return {
            "records": records,
            "protocol_counts": dict(protocols),
            "ipv4_count": sum(1 for r in records if "." in r["Source"] and r["Source"] != "—"),
            "ipv6_count": sum(1 for r in records if ":" in r["Source"] or ":" in r["Destination"]),
            "top_endpoints": top_endpoints,
        }
