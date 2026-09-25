import io
import pandas as pd
import streamlit as st

from config import settings
from sniffer import NetworkSniffer
from analyzer import PacketAnalyzer
from exporters import export_csv, export_json, export_markdown

st.set_page_config(page_title="NetScope — Basic Network Sniffer", page_icon="🌐", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
.block-container { padding-top: 1.4rem; }
.hero { padding: 1.35rem 1.5rem; border: 1px solid rgba(127,127,127,.18); border-radius: 20px; margin-bottom: 1rem; background: linear-gradient(135deg, rgba(79,70,229,.12), rgba(14,165,233,.10)); }
.safe { padding: .8rem 1rem; border-radius: 12px; border: 1px solid rgba(14,165,233,.25); background: rgba(14,165,233,.06); }
</style>
""", unsafe_allow_html=True)

if "analysis" not in st.session_state:
    st.session_state.analysis = None

sniffer = NetworkSniffer()
analyzer = PacketAnalyzer()

with st.sidebar:
    st.title("🌐 NetScope")
    st.caption("Basic network traffic learning workspace")
    st.divider()
    st.subheader("Capture settings")
    capture_mode = st.radio("Source", ["Demo traffic", "Live interface", "PCAP file"])
    interface = None
    if capture_mode == "Live interface":
        interfaces = sniffer.list_interfaces()
        if interfaces:
            selected = st.selectbox("Network interface", ["Auto"] + interfaces)
            interface = None if selected == "Auto" else selected
        else:
            st.warning("No interfaces detected by Scapy.")
    packet_count = st.slider("Packet limit", 5, min(200, settings.max_packets), 25, 5)
    timeout = st.slider("Capture timeout (seconds)", 1, 30, 8)
    show_payload = st.checkbox("Show payload preview", value=False, help="Payloads can contain sensitive data. Keep this off unless you are analyzing traffic you own or a lab capture.")
    st.divider()
    st.markdown('<div class="safe"><b>Safety note:</b> Capture only traffic on systems and networks you own or are explicitly authorized to test. Payload previews are optional and truncated.</div>', unsafe_allow_html=True)

st.markdown("""
<div class="hero"><h1>🌐 NetScope — Basic Network Sniffer</h1><p>Capture or load packets, inspect their structure, identify protocols, and understand how source/destination information travels through a network.</p></div>
""", unsafe_allow_html=True)

st.subheader("1. Collect Traffic")
uploaded_pcap = None
if capture_mode == "PCAP file":
    uploaded_pcap = st.file_uploader("Upload a PCAP/PCAPNG capture", type=["pcap", "pcapng"], help="Use a capture created on your own machine or a permitted lab dataset.")
collect = st.button("📡 Start Capture / Load Traffic", type="primary", use_container_width=True)

if collect:
    try:
        if capture_mode == "Demo traffic":
            packets = sniffer.demo_packets(packet_count)
            label = "Demo traffic"
        elif capture_mode == "Live interface":
            with st.spinner("Capturing packets..."):
                packets = sniffer.capture_live(iface=interface, count=packet_count, timeout=timeout)
            label = f"Live capture • {interface or 'auto interface'}"
        else:
            if uploaded_pcap is None:
                st.error("Please upload a PCAP or PCAPNG file first.")
                st.stop()
            raw = uploaded_pcap.getvalue()
            with st.spinner("Reading capture file..."):
                packets = sniffer.read_pcap(io.BytesIO(raw))
            label = f"PCAP • {uploaded_pcap.name}"
        records = analyzer.packet_records(packets, show_payload=show_payload)
        st.session_state.analysis = analyzer.analyze(records)
        st.session_state.analysis["capture_label"] = label
        st.success(f"Loaded {len(records)} packets from {label}.")
    except Exception as exc:
        st.error(f"Capture failed: {exc}")
        st.info("On Windows, live capture normally requires Npcap and may require an elevated terminal depending on the interface/driver.")

if st.session_state.analysis:
    analysis = st.session_state.analysis
    records = analysis["records"]
    st.divider()
    st.subheader("2. Traffic Overview")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", len(records))
    c2.metric("Protocols", len(analysis["protocol_counts"]))
    c3.metric("IPv4 packets", analysis["ipv4_count"])
    c4.metric("IPv6 packets", analysis["ipv6_count"])

    t1, t2, t3, t4 = st.tabs(["📋 Packet Table", "📊 Protocol Analysis", "🧱 Packet Structure", "💾 Export"])
    with t1:
        df = pd.DataFrame(records)
        cols = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Payload Preview"]
        st.dataframe(df[[c for c in cols if c in df.columns]], use_container_width=True, hide_index=True)
    with t2:
        protocol_df = pd.DataFrame([{"Protocol": k, "Packets": v} for k, v in analysis["protocol_counts"].items()])
        if not protocol_df.empty:
            st.bar_chart(protocol_df.set_index("Protocol"))
            st.dataframe(protocol_df, use_container_width=True, hide_index=True)
        st.markdown("### Source / Destination summary")
        st.dataframe(pd.DataFrame(analysis["top_endpoints"]), use_container_width=True, hide_index=True)
    with t3:
        if records:
            selected_no = st.selectbox("Select packet", [r["No."] for r in records])
            selected = next(r for r in records if r["No."] == selected_no)
            st.markdown(f"**Packet {selected['No.']}**")
            st.json(selected["layers"])
            st.write(selected["details"])
            if selected.get("Payload Preview"):
                st.markdown("**Truncated payload preview**")
                st.code(selected["Payload Preview"])
            st.caption("A packet is represented as a stack of protocol layers, for example Ethernet → IPv4/IPv6 → TCP/UDP → application data.")
    with t4:
        st.download_button("⬇ Markdown report", export_markdown(analysis), file_name="network_capture_report.md", mime="text/markdown", use_container_width=True)
        st.download_button("⬇ CSV packet table", export_csv(records), file_name="network_packets.csv", mime="text/csv", use_container_width=True)
        st.download_button("⬇ JSON analysis", export_json(analysis), file_name="network_analysis.json", mime="application/json", use_container_width=True)
    st.divider()
    st.subheader("3. Learning Notes")
    st.write("Use the packet table to identify source and destination addresses, then open a packet to inspect its protocol-layer structure. Compare protocol counts to understand how different traffic appears in a capture.")
    st.caption("This tool is educational. It does not decrypt encrypted traffic or attempt to recover passwords, tokens, or credentials.")
else:
    st.info("Start with Demo traffic to verify the UI without capturing real network traffic.")

st.divider()
st.caption("NetScope • Packet metadata first • Payload preview off by default")
