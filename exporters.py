import json
import pandas as pd
def export_csv(records):
    df = pd.DataFrame(records)
    if "layers" in df.columns: df = df.drop(columns=["layers"])
    return df.to_csv(index=False)
def export_json(analysis):
    return json.dumps(analysis, indent=2, ensure_ascii=False, default=str)
def export_markdown(analysis):
    lines = [
        "# NetScope Network Capture Report", "",
        f"- Packets: {len(analysis['records'])}",
        f"- Protocols observed: {', '.join(analysis['protocol_counts'].keys()) or 'None'}",
        f"- IPv4 packets: {analysis['ipv4_count']}",
        f"- IPv6 packets: {analysis['ipv6_count']}", "", "## Protocol Counts"
    ]
    for proto, count in analysis["protocol_counts"].items(): lines.append(f"- {proto}: {count}")
    lines += ["", "## Packets"]
    for r in analysis["records"]:
        lines.append(f"- #{r['No.']} | {r['Source']} → {r['Destination']} | {r['Protocol']} | {r['Length']} bytes | {r['Info']}")
    lines += ["", "## Safety / Interpretation", "Payload previews are optional and truncated. Packet metadata can still reveal network relationships, so captures should be handled as potentially sensitive data."]
    return "\n".join(lines)
