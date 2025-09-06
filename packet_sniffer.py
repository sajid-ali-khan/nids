from scapy.all import sniff
from packet_saver import save_flow
from feature_vector_extractor import extract_feature_vector

flows = {}

packets = sniff(prn=lambda x: save_flow(flows, x), timeout=10, filter="tcp or udp")
print(f'#packets = {len(packets)}, #flows = {len(flows)}')

# for key, flow in flows.items():
#     print(f"Flow {key}: Fwd packets = {flow["fwd_packets"]}, Bwd packets = {flow["bwd_packets"]}")
#     print(f"Bytes: Fwd = {flow["fwd_bytes"]}, Bwd = {flow["bwd_bytes"]}")
#     print(f"TCP Flags: {flow["tcp_flags"]}")
#     print(f"Flow duration: {flow["last_time"] - flow["start_time"]}\n")

for flow in flows.values():
    extract_feature_vector(flow)
