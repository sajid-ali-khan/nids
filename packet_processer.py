from scapy.all import TCP, UDP, IP

def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        src = ip.src
        dest = ip.dst
        protocol = ip.proto
        packet_size = len(packet)
        
        if packet.haslayer(TCP):
            ptype = "TCP"
        elif packet.haslayer(UDP):
            ptype = "UDP"
        else:
            return (None, 0, None)
        
        sport = packet[ptype].sport
        dport = packet[ptype].dport
        
        # Create key with sorted tuples for bidirectional matching
        src_tuple = (src, sport)
        dest_tuple = (dest, dport)
        key = (tuple(sorted([src_tuple, dest_tuple])), protocol)
        return (key, packet_size, src_tuple)
    
    return (None, 0, None)
