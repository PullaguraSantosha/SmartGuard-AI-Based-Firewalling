import time
import threading
from collections import defaultdict, deque
from scapy.all import sniff, IP, ICMP, TCP, UDP

# ------------------- CONFIGURATION --------------------
WINDOW_SIZE = 5  # seconds for stats print interval

# ---- ICMP Thresholds ----
ICMP_RATE_THRESHOLD = 1000          # packets/sec
ICMP_SPOOFED_SRC_THRESHOLD = 150    # unique source IPs
ICMP_LARGE_PAYLOAD_THRESHOLD = 1400 # bytes

# ---- TCP SYN Thresholds ----
TCP_SYN_PPS_THRESHOLD = 1000
TCP_UNIQUE_SPORT_THRESHOLD = 500
TCP_AVG_PKT_SIZE_THRESHOLD = 100

# ---- UDP Thresholds ----
UDP_RATE_THRESHOLD = 200
UDP_LARGE_PAYLOAD_THRESHOLD = 1000
UDP_PORT_VARIATION_THRESHOLD = 50

# ------------------- ICMP STATE ------------------------
icmp_packet_times = deque()
icmp_src_ip_count = defaultdict(int)
icmp_large_payload_count = 0
icmp_lock = threading.Lock()
icmp_payload_counter = defaultdict(int)

# ------------------- TCP SYN STATE ---------------------
tcp_syn_packet_times = deque()
tcp_source_ports = defaultdict(set)  # key: timestamp, value: set of source ports
tcp_packet_sizes = []
tcp_lock = threading.Lock()

# ------------------- UDP STATE -------------------------
udp_packet_times = deque()
udp_dst_port_counter = defaultdict(int)
udp_large_payload_count = 0
udp_lock = threading.Lock()

# ------------------- ICMP HANDLER ----------------------
def detect_icmp(pkt):
    global icmp_large_payload_count
    if not pkt.haslayer(ICMP) or pkt[ICMP].type != 8:
        return
    now = time.time()
    with icmp_lock:
        icmp_packet_times.append(now)
        ip_src = pkt[IP].src
        icmp_src_ip_count[ip_src] += 1
        payload = bytes(pkt[ICMP].payload)
        icmp_payload_counter[payload] += 1
        if len(payload) > ICMP_LARGE_PAYLOAD_THRESHOLD:
            icmp_large_payload_count += 1

# ------------------- TCP HANDLER -----------------------
def detect_tcp(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return
    now = time.time()
    flags = pkt[TCP].flags
    if flags != "S":
        return  # Only SYN packets
    sport = pkt[TCP].sport
    pkt_len = len(pkt)
    with tcp_lock:
        tcp_syn_packet_times.append(now)
        tcp_source_ports[now].add(sport)
        tcp_packet_sizes.append(pkt_len)

# ------------------- UDP HANDLER -----------------------
def detect_udp(pkt):
    global udp_large_payload_count
    if not pkt.haslayer(UDP):
        return
    now = time.time()
    with udp_lock:
        udp_packet_times.append(now)
        port = pkt[UDP].dport
        udp_dst_port_counter[port] += 1
        payload = bytes(pkt[UDP].payload)
        if len(payload) > UDP_LARGE_PAYLOAD_THRESHOLD:
            udp_large_payload_count += 1

# ------------------- MASTER PACKET HANDLER -------------------
def master_packet_handler(pkt):
    if pkt.haslayer(ICMP):
        detect_icmp(pkt)
    elif pkt.haslayer(TCP):
        detect_tcp(pkt)
    elif pkt.haslayer(UDP):
        detect_udp(pkt)

# ------------------- COMBINED STATS PRINTER -------------------
def print_combined_stats():
    global icmp_large_payload_count, udp_large_payload_count

    while True:
        time.sleep(WINDOW_SIZE)
        now = time.time()

        # --- ICMP Analysis ---
        with icmp_lock:
            while icmp_packet_times and icmp_packet_times[0] < now - WINDOW_SIZE:
                icmp_packet_times.popleft()

            icmp_pps = len(icmp_packet_times) / WINDOW_SIZE
            icmp_spoofed_ips = len(icmp_src_ip_count)
            icmp_lpayload_count = icmp_large_payload_count

            # Reset for next window
            icmp_src_ip_count.clear()
            icmp_payload_counter.clear()
            icmp_large_payload_count = 0

        icmp_flood_pps_variant = int(icmp_pps > ICMP_RATE_THRESHOLD)
        icmp_flood_large_payload_variant = int(icmp_lpayload_count > 10)
        icmp_flood_spoofed_ips_variant = int(icmp_spoofed_ips > ICMP_SPOOFED_SRC_THRESHOLD)

        # --- TCP Analysis ---
        with tcp_lock:
            while tcp_syn_packet_times and tcp_syn_packet_times[0] < now - WINDOW_SIZE:
                tcp_syn_packet_times.popleft()

            tcp_current_syns = len(tcp_syn_packet_times)
            tcp_syn_pps = tcp_current_syns / WINDOW_SIZE

            active_ports = set()
            expired_keys = []
            for t, ports in tcp_source_ports.items():
                if t < now - WINDOW_SIZE:
                    expired_keys.append(t)
                else:
                    active_ports |= ports
            for k in expired_keys:
                del tcp_source_ports[k]
            tcp_unique_sports = len(active_ports)

            tcp_avg_pkt_size = (sum(tcp_packet_sizes) / len(tcp_packet_sizes)) if tcp_packet_sizes else 0
            tcp_packet_sizes.clear()

        # --- UDP Analysis ---
        with udp_lock:
            while udp_packet_times and udp_packet_times[0] < now - WINDOW_SIZE:
                udp_packet_times.popleft()
            udp_pps = len(udp_packet_times) / WINDOW_SIZE
            udp_unique_ports = len(udp_dst_port_counter)
            udp_lpayload_count = udp_large_payload_count

            # Reset for next window
            udp_dst_port_counter.clear()
            udp_large_payload_count = 0

        udp_flood_pps_variant = int(udp_pps > UDP_RATE_THRESHOLD)
        udp_flood_large_payload_variant = int(udp_lpayload_count > 10)
        udp_flood_port_variation_variant = int(udp_unique_ports > UDP_PORT_VARIATION_THRESHOLD)

        # --- PRINT ALL TOGETHER ---
        print("\n" + "="*60)
        print(f"📅 Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)

        # ICMP Report
        print("\n📊 ICMP Attack Indicators\n-------------------------")
        print(f"  📦 1. Standard ICMP Flood (PPS > {ICMP_RATE_THRESHOLD}): {icmp_pps:.2f} packets/sec")
        print(f"  🌐 2. High Payload ICMP Flood (Payload > {ICMP_LARGE_PAYLOAD_THRESHOLD} bytes): {icmp_lpayload_count}")
        print(f"  🧱 3. Spoofed ICMP Flood (Unique Src IPs > {ICMP_SPOOFED_SRC_THRESHOLD}): {icmp_spoofed_ips}")
        if icmp_flood_pps_variant or icmp_flood_large_payload_variant or icmp_flood_spoofed_ips_variant:
            print("\n🚨 ALERT: 🔥 ICMP Flood Attack detected")
            if icmp_flood_pps_variant:
                print("     - Variant: Standard ICMP Flood")
            if icmp_flood_large_payload_variant:
                print("     - Variant: High Payload ICMP Flood")
            if icmp_flood_spoofed_ips_variant:
                print("     - Variant: Spoofed ICMP Flood")
        else:
            print("✅ No ICMP Flood detected.")

        # TCP Report
        print("\n📊 TCP SYN Flood Detection Report\n-------------------------------")
        print(f"  📦 SYN PPS           : {tcp_syn_pps:.2f}")
        print(f"  🔢 Unique Src Ports  : {tcp_unique_sports}")
        print(f"  📏 Avg Packet Size   : {tcp_avg_pkt_size:.2f} bytes")
        alerts = []
        if tcp_syn_pps > TCP_SYN_PPS_THRESHOLD:
            alerts.append("High SYN PPS")
        if tcp_unique_sports > TCP_UNIQUE_SPORT_THRESHOLD:
            alerts.append("High Unique Src Ports/sec")
        if 10 < tcp_avg_pkt_size < TCP_AVG_PKT_SIZE_THRESHOLD:
            alerts.append("Low Avg Packet Size")
        if alerts:
            print("\n🚨 ALERT: Features detected:")
            for alert in alerts:
                print(f"     - {alert}")
        else:
            print("✅ No TCP SYN Flood detected.")

        # UDP Report
        print("\n📊 UDP Attack Indicators\n-------------------------")
        print(f"  📦 1. Packet Rate (PPS > {UDP_RATE_THRESHOLD}): {udp_pps:.2f} packets/sec")
        print(f"  🔁 2. Unique Dest Ports (> {UDP_PORT_VARIATION_THRESHOLD}): {udp_unique_ports}")
        print(f"  💾 3. Large Payload Count (> 10): {udp_lpayload_count}")
        if udp_flood_pps_variant or udp_flood_large_payload_variant or udp_flood_port_variation_variant:
            print("\n🚨 ALERT: 🔥 UDP Flood Attack Detected")
            if udp_flood_pps_variant:
                print("     - Variant: Standard UDP Flood (High PPS)")
            if udp_flood_large_payload_variant:
                print("     - Variant: Large Payload UDP Flood")
            if udp_flood_port_variation_variant:
                print("     - Variant: Random Port UDP Flood")
        else:
            print("✅ No UDP Flood detected.")

        print("="*60 + "\n")

# ------------------- MAIN -------------------------
if __name__ == "__main__":
    iface = "eth0"  # Change this to your network interface

    print(f"\n🚦 Monitoring ICMP, TCP, UDP packets on interface '{iface}'")
    print(f"🕒 Combined traffic summary every {WINDOW_SIZE} seconds.\n")

    # Start combined stats printing thread
    threading.Thread(target=print_combined_stats, daemon=True).start()

    # Start sniffing packets
    sniff(iface=iface, prn=master_packet_handler, store=0)
