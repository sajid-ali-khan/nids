def initialize_flow(start_time):
    flow = {}
    flow["start_time"] = start_time
    flow["last_time"] = start_time
    flow["fwd_packets"] = 0
    flow["bwd_packets"] = 0
    flow["fwd_bytes"] = 0
    flow["bwd_bytes"] = 0
    flow["fwd_pkt_lengths"] = []
    flow["bwd_pkt_lengths"] = []
    flow["fwd_iat"] = []  # Inter-arrival times for forward packets
    flow["bwd_iat"] = []  # Inter-arrival times for backward packets
    flow["tcp_flags"] = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0, "CWE": 0, "ECE": 0}
    flow["fwd_header_lengths"] = []
    flow["bwd_header_lengths"] = []
    flow["fwd_timestamps"] = []
    flow["bwd_timestamps"] = []
    flow["active_times"] = []
    flow["idle_times"] = []
    return flow