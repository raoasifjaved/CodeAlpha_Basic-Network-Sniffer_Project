# START HERE — NetScope

## 1. Create environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 2. Install
```powershell
pip install -r requirements.txt
```

## 3. Configure
```powershell
Copy-Item .env.example .env
```

## 4. Verify
```powershell
python run_checks.py
```

## 5. First safe run
```powershell
streamlit run app.py
```
Select **Demo traffic** and click **Start Capture / Load Traffic**.

## 6. Study packet structure
Open **Packet Structure**, select a packet, and inspect the `layers` list.

## 7. Study protocols
Open **Protocol Analysis** and compare TCP, UDP, ICMP, IPv4, and IPv6 counts.

## 8. Live capture
Install Npcap on Windows, choose a local interface, keep payload preview off initially, and capture a small number of packets.

## 9. PCAP learning
Use a capture from your own lab and load it in **PCAP file** mode.

## 10. Screenshots for an assignment
Recommended order:
1. NetScope home screen
2. Capture settings
3. Demo/live capture
4. Packet table with source/destination/protocol
5. Protocol analysis chart
6. Packet structure view
7. Controlled payload preview
8. Exported report
