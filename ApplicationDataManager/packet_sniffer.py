import logging
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import hashlib
import csv
import time
import os


# Configure logging
log_filename = 'packet_log.txt'
csv_filename = 'packet_log.csv'

logging.basicConfig(filename=log_filename, level=logging.INFO,
                    format='%(asctime)s | %(levelname)s | %(message)s', datefmt='%H:%M:%S')

flow_info = {}

# Mapping protocol numbers to names
protocol_names = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP",
    10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP",
    18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1",
    26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP",
    34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP",
    43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP", 51: "AH",
    52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 62: "CFTP", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 69: "SAT-MON", 70: "VISA",
    71: "IPCU", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK",
    80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 84: "IPTM", 85: "NSFNET-IGP", 86: "DGP",
    87: "TCF", 88: "EIGRP", 89: "OSPFIGP", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "OS", 95: "MICP",
    96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS",
    106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP", 113: "PGM",
    115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "ISIS",
    125: "FIRE", 126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC",
    134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6",
    141: "WESP", 142: "ROHC",
}

def get_protocol_name(packet):
    if IP in packet:
        protocol_num = packet[IP].proto
        return protocol_names.get(protocol_num, "Unknown")

def get_protocol_service(packet):
    if IP in packet:
        protocol_num = packet[IP].proto
        protocol_name = protocol_names.get(protocol_num, "Unknown")
        service = ""

        port_service_mapping = {
        20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 80: "HTTP",
        110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 514: "Syslog",
        636: "LDAPS", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9090: "HTTP-Alt3",
        10000: "Webmin", 27017: "MongoDB", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
        }


        if TCP in packet:
            dst_port = packet[TCP].dport
            service = port_service_mapping.get(dst_port, "")

        elif UDP in packet:
            dst_port = packet[UDP].dport
            service = port_service_mapping.get(dst_port, "")

        return protocol_name, service

    return "Unknown", ""

def print_packet_info(packet, csv_writer1,csv_writer2):
    if IP in packet:
        timestamp = datetime.now().strftime('%H:%M:%S')
        date = datetime.now().strftime('%Y-%m-%d')
        protocol = get_protocol_name(packet)
        service = get_protocol_service(packet)
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet.sport if TCP in packet else packet[UDP].sport if UDP in packet else ""
        dst_port = packet.dport if TCP in packet else packet[UDP].dport if UDP in packet else ""
        payload = packet[Raw].load.decode(errors="ignore").replace('\n', '') if Raw in packet else ""
        print(payload)
        md5_hash = hashlib.md5(payload.encode()).hexdigest()
        flags = packet.sprintf("%TCP.flags%") if TCP in packet else ""
        # Update flow information
        flow_key = (ip_src, src_port, ip_dst, dst_port)
        if flow_key in flow_info:
            flow_info[flow_key]['packet_count'] += 1
            flow_info[flow_key]['total_bytes'] += len(payload)
            flow_info[flow_key]['end_time'] = timestamp
        else:
            flow_info[flow_key] = {
                'packet_count': 1,
                'total_bytes': len(payload),
                'start_time': timestamp,
                'end_time': timestamp
            }
        with open('hash.txt','r') as f:
                for FILE_hash in f:
                    if md5_hash==FILE_hash.strip():
                        print("malicious")
                        log_entry_csv_M = [timestamp, date, protocol, ip_src, ip_dst, src_port, dst_port, md5_hash, flags, len(payload),
                        flow_info[flow_key]['packet_count'], flow_info[flow_key]['start_time'],
                        flow_info[flow_key]['end_time'],str(service[1])]
                        csv_writer2.writerow(log_entry_csv_M)
        # Dynamically format the log entry
        log_entry = "{:<10} |   {:<10} |    {:<8} |     {:<15} |    {:<15} |    {:<10} |    {:<10} |    {:<10} |    {:<10} |   {:<10}   |    {:<10}   |    {:<10} |    {:<10}  | {:<10} ".format(
            timestamp, date, protocol, ip_src, ip_dst, src_port, dst_port, md5_hash, flags, len(payload),
            flow_info[flow_key]['packet_count'], flow_info[flow_key]['start_time'], flow_info[flow_key]['end_time'],str(service[1])        
        )

        log_entry_csv = [timestamp, date, protocol, ip_src, ip_dst, src_port, dst_port, md5_hash, flags, len(payload),
                         flow_info[flow_key]['packet_count'], flow_info[flow_key]['start_time'],
                         flow_info[flow_key]['end_time'],str(service[1])]
        csv_writer1.writerow(log_entry_csv)

        # Log to console and file
        print(log_entry)
        logging.info(log_entry)

def packet_sniffer():
    print("Starting packet sniffer...")
    logging.info("Packet sniffer started.")
    log_entry = "{:<10} |   {:<10} |    {:<8} |     {:<15} |    {:<15} |    {:<10} |    {:<10} |    {:<32} |    {:<10} |   {:<10}   |   {:<10}  |   {:<10}  |   {:<10}  | {:<10} ".format(
        "TIME-STAMP", "DATE", "PROTOCOL", "SRC-IP", "DST-IP", "SRC-PORT", "DST-PORT", "MD5-HASH", "FLAGS", "PAYLOAD-LEN",
        "PACKET-COUNT", "START_TIME", "END-TIME","SERVICE-TYPE"
    )
    print(log_entry)
    # Initialize CSV file
    if not os.path.exists(csv_filename):
        with open(csv_filename, 'w', newline='') as csv_file:
            csv_writer1 = csv.writer(csv_file)
            header = ["TIME-STAMP", "DATE", "PROTOCOL", "SRC-IP", "DST-IP", "SRC-PORT", "DST-PORT", "MD5-HASH", "FLAGS",
                      "PAYLOAD SIZE","PACKET-COUNT","START_TIME","END-TIME","SERVICE_TYPE"]
            csv_writer1.writerow(header)
    with open('malicious.csv', 'w', newline='') as csv_file:
        csv_writer2 = csv.writer(csv_file)
        header = ["TIME-STAMP", "DATE", "PROTOCOL", "SRC-IP", "DST-IP", "SRC-PORT", "DST-PORT", "MD5-HASH", "FLAGS","PAYLOAD SIZE","PACKET-COUNT","START_TIME","END-TIME","SERVICE_TYPE"]
        csv_writer2.writerow(header)
    try:
        while True:
            with open(csv_filename, 'a', newline='') as csv_file1, open('malicious.csv', 'a', newline='') as csv_file2:
                csv_writer1 = csv.writer(csv_file1)
                csv_writer2 = csv.writer(csv_file2)
                sniff(prn=lambda pkt: print_packet_info(pkt, csv_writer1,csv_writer2), store=False, iface=['eth0', 'lo'], timeout=5)
    except KeyboardInterrupt:
        print("\nPacket sniffer terminated by user.")
        logging.info("Packet sniffer terminated by user.")
        exit()

if __name__ == "__main__":
    packet_sniffer()

