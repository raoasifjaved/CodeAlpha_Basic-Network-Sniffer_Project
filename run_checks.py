from pathlib import Path
import ast
BASE = Path(__file__).resolve().parent
PY_FILES = ["app.py", "config.py", "sniffer.py", "analyzer.py", "exporters.py", "run_checks.py"]
print("[1/6] Checking Python syntax...")
for name in PY_FILES:
    ast.parse((BASE/name).read_text(encoding="utf-8"), filename=name)
print("      PASS")
try:
    import scapy.all as _  # noqa
    scapy_ok = True
except Exception as exc:
    scapy_ok = False
    print(f"[2/6] Scapy import: SKIP in this environment ({exc})")
if scapy_ok:
    print("[2/6] Scapy import...\n      PASS")
    from sniffer import NetworkSniffer
    from analyzer import PacketAnalyzer
    from scapy.all import IP, TCP, Raw
    packets = NetworkSniffer().demo_packets(8)
    print("[3/6] Demo packet generation...\n      PASS")
    analyzer = PacketAnalyzer()
    records = analyzer.packet_records(packets, show_payload=False)
    assert len(records) == 8 and all(r["Payload Preview"] == "" for r in records)
    print("[4/6] Packet parsing without payload exposure...\n      PASS")
    preview = analyzer.packet_records([IP(src="127.0.0.1", dst="127.0.0.1")/TCP()/Raw(load=b"safe-demo")], show_payload=True)
    assert preview[0]["Payload Preview"].startswith("safe-demo")
    analysis = analyzer.analyze(records)
    assert "TCP" in analysis["protocol_counts"]
    print("[5/6] Protocol analysis and controlled payload preview...\n      PASS")
    from exporters import export_csv, export_json, export_markdown
    assert "Protocol" in export_csv(records) and '"protocol_counts"' in export_json(analysis) and "# NetScope" in export_markdown(analysis)
    print("[6/6] Export checks...\n      PASS")
else:
    for n, title in [(3,"Demo packet generation"),(4,"Packet parsing"),(5,"Protocol/payload analysis"),(6,"Export checks")]:
        print(f"[{n}/6] {title}...\n      SKIP (requires Scapy)")
print("\nCHECKS COMPLETE")
