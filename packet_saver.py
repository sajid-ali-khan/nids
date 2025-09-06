from packet_processer import process_packet
from flow_model import initialize_flow
from scapy.all import TCP

def save_flow(flows, packet):
    key, packet_size, src_tuple = process_packet(packet)
    # print(key)
    if key is None:
        return
    
    if key not in flows:
        flows[key] = initialize_flow(packet.time)
    
    flow = flows[key]
    flow["last_time"] = packet.time

    
    if src_tuple == key[0][0]:  # Forward direction
        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += packet_size
        flow["fwd_pkt_lengths"].append(packet_size)
    else:  # Backward direction
        flow["bwd_packets"] += 1
        flow["bwd_bytes"] += packet_size
        flow["bwd_pkt_lengths"].append(packet_size)
    
    # Check TCP flags if TCP packet
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.flags & 0x02: flow["tcp_flags"]["SYN"] += 1
        if tcp.flags & 0x10: flow["tcp_flags"]["ACK"] += 1
        if tcp.flags & 0x01: flow["tcp_flags"]["FIN"] += 1
        if tcp.flags & 0x04: flow["tcp_flags"]["RST"] += 1

