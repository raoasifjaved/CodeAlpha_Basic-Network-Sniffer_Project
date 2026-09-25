# NetScope — Basic Network Sniffer

An educational Python + Streamlit network sniffer for studying packet capture, protocol layers, and network metadata.

## Task 1 requirements
- Capture network traffic packets
- Analyze packet structure and content
- Learn data flow and protocol basics
- Use Scapy for packet capture
- Display source/destination IPs, protocols, and controlled payload previews

## Safety
Use only on systems and networks you own or are explicitly authorized to inspect. Payload preview is OFF by default because captured data may contain sensitive information. The application does not decrypt encrypted traffic or attempt to retrieve passwords, tokens, or credentials.

## Modes
1. Demo traffic — no live capture and no elevated privileges required.
2. Live interface — Scapy packet capture from a selected local interface.
3. PCAP file — offline analysis of a permitted capture.

## Windows
Live capture typically requires Npcap and may require an elevated terminal depending on interface/driver configuration.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python run_checks.py
streamlit run app.py
```

## Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run_checks.py
streamlit run app.py
```

## Packet structure
A common packet can be viewed as layered protocol data, for example: Ethernet -> IPv4/IPv6 -> TCP/UDP -> application payload.

## Payload handling
If payload preview is enabled, the UI shows at most 64 bytes using printable-character rendering and replaces non-printable bytes with dots. This is an educational preview, not a decoder.

## Accuracy
Packet length is measured from the captured Scapy packet object. IP addresses and protocol fields are read from packet headers. The tool does not infer a protocol that is not represented in the packet layers.

## Exports
- CSV packet table
- JSON analysis
- Markdown report
