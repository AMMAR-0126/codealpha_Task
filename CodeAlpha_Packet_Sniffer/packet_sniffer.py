#!/usr/bin/env python3
"""
Network Packet Sniffer — Kali Linux
=====================================
Scapy se packet capturing aur analysis
Run karo: sudo python3 packet_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, Ether
import datetime
import sys

# ========== CONFIGURATION ==========
INTERFACE   = "wlan0"   # apna interface yahan likhna (eth0, wlan0, etc.)
PKT_COUNT   = 50       # 0 = unlimited
SHOW_PAYLOAD = True    # Raw data dikhana?
FILTER      = ""       # BPF filter, e.g. "tcp port 80" ya "" for all
# ====================================

packet_count = 0

COMMON_PORTS = {
    20: "FTP-Data",  21: "FTP",     22: "SSH",
    23: "Telnet",    25: "SMTP",    53: "DNS",
    80: "HTTP",      110: "POP3",   143: "IMAP",
    443: "HTTPS",    3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Alt",8443: "HTTPS-Alt",
}

def get_service(port):
    return COMMON_PORTS.get(port, f"Port-{port}")

def format_payload(raw_bytes, max_len=100):
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        text = "".join(c if c.isprintable() else "." for c in text)
        return text[:max_len] + ("..." if len(text) > max_len else "")
    except Exception:
        return repr(raw_bytes[:40])

def analyze_packet(pkt):
    global packet_count
    packet_count += 1
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"\n{'═' * 58}")
    print(f"  📦  Packet #{packet_count:<4}  |  {ts}  |  {len(pkt)} bytes")
    print(f"{'═' * 58}")

    # --- Layer 2: Ethernet ---
    if Ether in pkt:
        eth = pkt[Ether]
        print(f"  [L2] Ethernet  {eth.src}  →  {eth.dst}")

    # --- Layer 3: IP ---
    if IP in pkt:
        ip = pkt[IP]
        print(f"  [L3] IP        {ip.src:<18} →  {ip.dst}")
        print(f"       TTL={ip.ttl}  Version=IPv{ip.version}  ID={ip.id}")

        # --- Layer 4: TCP ---
        if TCP in pkt:
            tcp = pkt[TCP]
            flags = tcp.flags
            flag_str = []
            if flags.S: flag_str.append("SYN")
            if flags.A: flag_str.append("ACK")
            if flags.F: flag_str.append("FIN")
            if flags.R: flag_str.append("RST")
            if flags.P: flag_str.append("PSH")
            flags_disp = "+".join(flag_str) if flag_str else str(flags)

            src_svc = get_service(tcp.sport)
            dst_svc = get_service(tcp.dport)

            print(f"  [L4] TCP       {ip.src}:{tcp.sport} ({src_svc})")
            print(f"            →    {ip.dst}:{tcp.dport} ({dst_svc})")
            print(f"       Flags=[{flags_disp}]  Seq={tcp.seq}  Ack={tcp.ack}")
            print(f"       Win={tcp.window}  Len={len(tcp.payload)} bytes payload")

        # --- Layer 4: UDP ---
        elif UDP in pkt:
            udp = pkt[UDP]
            src_svc = get_service(udp.sport)
            dst_svc = get_service(udp.dport)
            print(f"  [L4] UDP       {ip.src}:{udp.sport} ({src_svc})")
            print(f"            →    {ip.dst}:{udp.dport} ({dst_svc})")

            # DNS query detect
            if DNS in pkt:
                try:
                    qd = pkt[DNS].qd
                    if qd:
                        qname = qd.qname.decode().rstrip(".")
                        qtype = {1:"A", 28:"AAAA", 15:"MX", 16:"TXT"}.get(qd.qtype, str(qd.qtype))
                        print(f"  [L7] DNS Query: {qname} (Type={qtype})")
                except Exception:
                    pass

        # --- ICMP ---
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                          8: "Echo Request", 11: "Time Exceeded"}
            icmp_name = icmp_types.get(icmp.type, f"Type={icmp.type}")
            print(f"  [L4] ICMP      {ip.src}  →  {ip.dst}")
            print(f"       Type: {icmp_name}  Code={icmp.code}")

        else:
            print(f"  [L4] Proto={ip.proto} (Unknown/Other)")

        # --- Payload ---
        if SHOW_PAYLOAD and Raw in pkt:
            payload = pkt[Raw].load
            print(f"  [L7] Payload ({len(payload)} bytes):")
            print(f"       {format_payload(payload)}")

    else:
        print(f"  [Non-IP Packet] Summary: {pkt.summary()}")

def main():
    print("=" * 58)
    print("   🔍  Network Packet Sniffer — Scapy + Python3")
    print("=" * 58)
    print(f"   Interface : {INTERFACE}")
    print(f"   Count     : {PKT_COUNT if PKT_COUNT else 'Unlimited'}")
    print(f"   Filter    : '{FILTER}' (blank = all)")
    print(f"   Payload   : {'ON' if SHOW_PAYLOAD else 'OFF'}")
    print(f"   Time      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 58)
    print("   Ctrl+C se band karo\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=analyze_packet,
            count=PKT_COUNT,
            store=0,
            filter=FILTER,
        )
    except KeyboardInterrupt:
        print(f"\n\n[✓] Capture band hua. Total packets: {packet_count}")
        sys.exit(0)
    except PermissionError:
        print("\n[✗] Permission denied! sudo se run karo:")
        print("    sudo python3 packet_sniffer.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

