"""
Sample PCAP Generator for AI-NIDS Testing and Portfolio Evaluation.
Generates realistic benchmark PCAPs matching CIC-IDS2017 traffic patterns:
1. Benign Web & DNS Traffic
2. Multi-probe Port Scan Attacks
3. High-Rate HTTP Flood / DoS Attacks
4. Mixed realistic traffic
"""

from pathlib import Path
import time
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import wrpcap

def generate_sample_pcaps(output_dir: Path = Path("data/sample_pcaps")) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    base_time = time.time() - 300.0

    # 1. Benign Traffic (HTTP & DNS)
    benign_packets = []
    t = base_time
    dns_query = IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=53123, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
    dns_query.time = t
    benign_packets.append(dns_query)

    t += 0.025
    dns_resp = IP(src="8.8.8.8", dst="192.168.1.105") / UDP(sport=53, dport=53123) / DNS(qr=1, an=DNSRR(rrname="www.google.com", rdata="142.250.190.46"))
    dns_resp.time = t
    benign_packets.append(dns_resp)

    # HTTP Normal browsing
    client_ip = "192.168.1.105"
    web_ip = "142.250.190.46"
    client_port = 49201
    server_port = 80

    t += 0.05
    syn = IP(src=client_ip, dst=web_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
    syn.time = t
    benign_packets.append(syn)

    t += 0.015
    synack = IP(src=web_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001)
    synack.time = t
    benign_packets.append(synack)

    t += 0.005
    ack = IP(src=client_ip, dst=web_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001)
    ack.time = t
    benign_packets.append(ack)

    t += 0.01
    http_get = IP(src=client_ip, dst=web_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2001) / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    http_get.time = t
    benign_packets.append(http_get)

    t += 0.03
    http_resp = IP(src=web_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1001 + len(http_get[TCP].payload)) / b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nHello, World!\n"
    http_resp.time = t
    benign_packets.append(http_resp)

    t += 0.01
    fin_cli = IP(src=client_ip, dst=web_ip) / TCP(sport=client_port, dport=server_port, flags="FA", seq=1001 + len(http_get[TCP].payload), ack=2001 + len(http_resp[TCP].payload))
    fin_cli.time = t
    benign_packets.append(fin_cli)

    t += 0.005
    fin_srv = IP(src=web_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="FA", seq=2001 + len(http_resp[TCP].payload), ack=fin_cli[TCP].seq + 1)
    fin_srv.time = t
    benign_packets.append(fin_srv)

    wrpcap(str(output_dir / "benign_traffic.pcap"), benign_packets)
    print(f"Generated benign_traffic.pcap ({len(benign_packets)} packets)")

    # 2. Port Scan Attack PCAP (Nmap style: multiple probes per port)
    scan_packets = []
    attacker_ip = "172.16.0.5"
    target_ip = "192.168.1.50"
    target_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]

    t = base_time + 10.0
    for sport_idx, dport in enumerate(target_ports):
        # Nmap sends multiple packets per targeted port
        sport = 45000 + sport_idx
        for p_idx in range(5):
            probe = IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags="S", seq=1000 + p_idx * 100) / (b"X" * 64)
            probe.time = t + (p_idx * 0.005)
            scan_packets.append(probe)
        t += 0.05

    wrpcap(str(output_dir / "port_scan_attack.pcap"), scan_packets)
    print(f"Generated port_scan_attack.pcap ({len(scan_packets)} packets)")

    # 3. DDoS Attack PCAP (Application/HTTP Flood with repetitive requests)
    ddos_packets = []
    target_ip = "192.168.1.100"
    target_port = 80
    botnet_ips = [f"198.51.100.{i}" for i in range(1, 11)]

    t = base_time + 30.0
    for bot_idx, bot_ip in enumerate(botnet_ips):
        bot_sport = 50000 + bot_idx
        # Each bot generates a rapid multi-packet flood flow
        for req_idx in range(12):
            pkt = IP(src=bot_ip, dst=target_ip) / TCP(sport=bot_sport, dport=target_port, flags="PA", seq=10000 + req_idx * 200, ack=5000) / b"GET /loadtest?query=ddos HTTP/1.1\r\nHost: target.internal\r\nUser-Agent: Botnet/1.0\r\n\r\n"
            pkt.time = t + (req_idx * 0.001)
            ddos_packets.append(pkt)
        t += 0.02

    wrpcap(str(output_dir / "ddos_attack.pcap"), ddos_packets)
    print(f"Generated ddos_attack.pcap ({len(ddos_packets)} packets)")

    # 4. Mixed Traffic PCAP
    mixed_packets = sorted(benign_packets + scan_packets + ddos_packets, key=lambda p: float(getattr(p, "time", 0)))
    wrpcap(str(output_dir / "mixed_traffic.pcap"), mixed_packets)
    print(f"Generated mixed_traffic.pcap ({len(mixed_packets)} packets)")

if __name__ == "__main__":
    generate_sample_pcaps()
