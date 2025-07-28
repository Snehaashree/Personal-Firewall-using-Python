from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging

# Setup logging
logging.basicConfig(filename="firewall.log", level=logging.INFO, format='%(asctime)s - %(message)s')

# Define your rule set
rules = {
    "block_ips": ["10.10.1.17"],       # Replace with attacker's IP
    "block_ports": [22, 80],           # SSH and HTTP ports
    "block_protocols": ["ICMP"]        # Block ping
}

# Packet inspection logic
def is_blocked(packet):
    if IP in packet:
        src_ip = packet[IP].src

        if src_ip in rules["block_ips"]:
            return True, f"Blocked IP {src_ip}"

        if TCP in packet and packet[TCP].dport in rules["block_ports"]:
            return True, f"Blocked TCP port {packet[TCP].dport}"

        if UDP in packet and packet[UDP].dport in rules["block_ports"]:
            return True, f"Blocked UDP port {packet[UDP].dport}"

        if ICMP in packet and "ICMP" in rules["block_protocols"]:
            return True, "Blocked ICMP Protocol"

    return False, ""

# Main packet handler
def process_packet(packet):
    blocked, reason = is_blocked(packet)
    summary = packet.summary()

    if blocked:
        log_msg = f"[BLOCKED] {summary} => {reason}"
        logging.info(log_msg)
        print(log_msg)
    else:
        print(f"[ALLOWED] {summary}")

# Entry point
if __name__ == "__main__":
    interface = "ens33"  # Replace with your correct interface
    print(f"🔒 Starting CLI Firewall on {interface}...\nLogging to firewall.log\n")
    sniff(prn=process_packet, store=0, iface=interface)
