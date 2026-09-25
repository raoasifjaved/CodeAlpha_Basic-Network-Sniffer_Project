from io import BytesIO
from scapy.all import sniff, rdpcap, IP, UDP, TCP, ICMP, Raw
class NetworkSniffer:
    def list_interfaces(self):
        try:
            from scapy.all import get_if_list
            return list(get_if_list())
        except Exception:
            return []
    def capture_live(self, iface=None, count=25, timeout=8):
        kwargs = {"count": max(1, int(count)), "timeout": timeout}
        if iface:
            kwargs["iface"] = iface
        return sniff(**kwargs)
    def read_pcap(self, file_like):
        raw = file_like.read()
        if not raw:
            raise ValueError("The capture file is empty.")
        return rdpcap(BytesIO(raw))
    def demo_packets(self, count=25):
        from scapy.all import IP, TCP, UDP, ICMP, Raw
        templates = [
            IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n"),
            IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=53000, dport=53) / Raw(load=b"DNS demo"),
            IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(),
            IP(src="10.0.0.5", dst="10.0.0.8") / TCP(sport=50000, dport=22, flags="S"),
        ]
        return [templates[i % len(templates)].copy() for i in range(max(1, int(count)))]
