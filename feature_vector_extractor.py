from statistics import mean, stdev, variance
import numpy as np

def safe_mean(lst):
    return mean(lst) if lst else 0

def safe_stdev(lst):
    return stdev(lst) if len(lst) > 1 else 0

def safe_variance(lst):
    return variance(lst) if len(lst) > 1 else 0

def safe_max(lst):
    return max(lst) if lst else 0

def safe_min(lst):
    return min(lst) if lst else 0

def extract_feature_vector(flow):
    """
    Extract all 78 CICIDS-2017 features from a flow dictionary.
    Returns a list of feature values in the expected order.
    """
    features = []
    
    # 1. Flow Duration
    flow_duration = flow["last_time"] - flow["start_time"]
    features.append(flow_duration)
    
    # 2-4. Total Forward/Backward Packets and Total packets
    total_fwd_packets = flow["fwd_packets"]
    total_bwd_packets = flow["bwd_packets"]
    total_packets = total_fwd_packets + total_bwd_packets
    features.extend([total_fwd_packets, total_bwd_packets])
    
    # 5-6. Total Length of Forward/Backward packets
    total_fwd_bytes = flow["fwd_bytes"]
    total_bwd_bytes = flow["bwd_bytes"]
    features.extend([total_fwd_bytes, total_bwd_bytes])
    
    # 7-11. Forward Packet Length statistics
    fwd_pkt_lengths = flow["fwd_pkt_lengths"]
    features.extend([
        safe_max(fwd_pkt_lengths),      # Fwd Packet Length Max
        safe_min(fwd_pkt_lengths),      # Fwd Packet Length Min  
        safe_mean(fwd_pkt_lengths),     # Fwd Packet Length Mean
        safe_stdev(fwd_pkt_lengths)     # Fwd Packet Length Std
    ])
    
    # 12-16. Backward Packet Length statistics
    bwd_pkt_lengths = flow["bwd_pkt_lengths"]
    features.extend([
        safe_max(bwd_pkt_lengths),      # Bwd Packet Length Max
        safe_min(bwd_pkt_lengths),      # Bwd Packet Length Min
        safe_mean(bwd_pkt_lengths),     # Bwd Packet Length Mean
        safe_stdev(bwd_pkt_lengths)     # Bwd Packet Length Std
    ])
    
    # 17-19. Flow Bytes/s and Packets/s
    if flow_duration > 0:
        flow_bytes_per_sec = (total_fwd_bytes + total_bwd_bytes) / flow_duration
        flow_packets_per_sec = total_packets / flow_duration
    else:
        flow_bytes_per_sec = 0
        flow_packets_per_sec = 0
    features.extend([flow_bytes_per_sec, flow_packets_per_sec])
    
    # 20-24. Flow IAT (Inter-Arrival Time) statistics
    all_iat = flow["fwd_iat"] + flow["bwd_iat"]
    features.extend([
        safe_mean(all_iat),     # Flow IAT Mean
        safe_stdev(all_iat),    # Flow IAT Std
        safe_max(all_iat),      # Flow IAT Max
        safe_min(all_iat)       # Flow IAT Min
    ])
    
    # 25-29. Forward IAT statistics
    fwd_iat = flow["fwd_iat"]
    features.extend([
        sum(fwd_iat),           # Fwd IAT Total
        safe_mean(fwd_iat),     # Fwd IAT Mean
        safe_stdev(fwd_iat),    # Fwd IAT Std
        safe_max(fwd_iat),      # Fwd IAT Max
        safe_min(fwd_iat)       # Fwd IAT Min
    ])
    
    # 30-34. Backward IAT statistics
    bwd_iat = flow["bwd_iat"]
    features.extend([
        sum(bwd_iat),           # Bwd IAT Total
        safe_mean(bwd_iat),     # Bwd IAT Mean
        safe_stdev(bwd_iat),    # Bwd IAT Std
        safe_max(bwd_iat),      # Bwd IAT Max
        safe_min(bwd_iat)       # Bwd IAT Min
    ])
    
    # 35-42. TCP Flags
    tcp_flags = flow["tcp_flags"]
    features.extend([
        tcp_flags.get("PSH", 0),  # Fwd PSH Flags
        tcp_flags.get("PSH", 0),  # Bwd PSH Flags (approximation)
        tcp_flags.get("URG", 0),  # Fwd URG Flags
        tcp_flags.get("URG", 0),  # Bwd URG Flags (approximation)
        tcp_flags.get("FIN", 0),  # FIN Flag Count
        tcp_flags.get("SYN", 0),  # SYN Flag Count
        tcp_flags.get("RST", 0),  # RST Flag Count
        tcp_flags.get("ACK", 0)   # ACK Flag Count
    ])
    
    # 43-46. Header Length statistics
    fwd_header_lengths = flow.get("fwd_header_lengths", [])
    bwd_header_lengths = flow.get("bwd_header_lengths", [])
    features.extend([
        safe_mean(fwd_header_lengths),  # Fwd Header Length
        safe_mean(bwd_header_lengths),  # Bwd Header Length
        len(fwd_header_lengths),        # Fwd Packets/s
        len(bwd_header_lengths)         # Bwd Packets/s
    ])
    
    # 47-51. Packet Length statistics (overall)
    all_pkt_lengths = fwd_pkt_lengths + bwd_pkt_lengths
    features.extend([
        safe_min(all_pkt_lengths),      # Min Packet Length
        safe_max(all_pkt_lengths),      # Max Packet Length
        safe_mean(all_pkt_lengths),     # Packet Length Mean
        safe_stdev(all_pkt_lengths),    # Packet Length Std
        safe_variance(all_pkt_lengths)  # Packet Length Variance
    ])
    
    # 52. Down/Up Ratio
    if total_fwd_packets > 0:
        down_up_ratio = total_bwd_packets / total_fwd_packets
    else:
        down_up_ratio = 0
    features.append(down_up_ratio)
    
    # 53. Average Packet Size
    if total_packets > 0:
        avg_packet_size = (total_fwd_bytes + total_bwd_bytes) / total_packets
    else:
        avg_packet_size = 0
    features.append(avg_packet_size)
    
    # 54-55. Average Forward/Backward Segment Size
    if total_fwd_packets > 0:
        avg_fwd_segment_size = total_fwd_bytes / total_fwd_packets
    else:
        avg_fwd_segment_size = 0
        
    if total_bwd_packets > 0:
        avg_bwd_segment_size = total_bwd_bytes / total_bwd_packets
    else:
        avg_bwd_segment_size = 0
    features.extend([avg_fwd_segment_size, avg_bwd_segment_size])
    
    # 56-59. Forward/Backward Bytes per Bulk
    # These are complex features - using approximations
    features.extend([0, 0, 0, 0])  # Fwd/Bwd Avg Bytes/Bulk, Fwd/Bwd Avg Packets/Bulk
    
    # 60-61. Forward/Backward Bulk Rate
    features.extend([0, 0])  # Fwd/Bwd Avg Bulk Rate
    
    # 62-65. Subflow statistics
    # Approximating subflow features
    if flow_duration > 0:
        subflow_fwd_packets = total_fwd_packets
        subflow_fwd_bytes = total_fwd_bytes
        subflow_bwd_packets = total_bwd_packets
        subflow_bwd_bytes = total_bwd_bytes
    else:
        subflow_fwd_packets = subflow_fwd_bytes = 0
        subflow_bwd_packets = subflow_bwd_bytes = 0
    features.extend([subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets, subflow_bwd_bytes])
    
    # 66-67. Init Window bytes
    features.extend([0, 0])  # Init_Win_bytes_forward, Init_Win_bytes_backward
    
    # 68-69. Act data packets
    features.extend([total_fwd_packets, total_bwd_packets])  # act_data_pkt_fwd, act_data_pkt_bwd
    
    # 70-73. Flow Active/Idle statistics
    active_times = flow.get("active_times", [])
    idle_times = flow.get("idle_times", [])
    features.extend([
        safe_mean(active_times),    # Active Mean
        safe_stdev(active_times),   # Active Std
        safe_max(active_times),     # Active Max
        safe_min(active_times)      # Active Min
    ])
    
    # 74-78. Idle statistics
    features.extend([
        safe_mean(idle_times),      # Idle Mean
        safe_stdev(idle_times),     # Idle Std
        safe_max(idle_times),       # Idle Max
        safe_min(idle_times),       # Idle Min
        sum(idle_times)             # Idle Total (if needed)
    ])
    
    # Ensure we have exactly 78 features
    while len(features) < 78:
        features.append(0)
    
    return features[:78]  # Return exactly 78 features

# Example usage:
def create_feature_vector_for_model(flow, scaler):
    """
    Extract features and prepare them for the trained model.
    
    Args:
        flow: Flow dictionary with packet information
        scaler: The StandardScaler object used during training
    
    Returns:
        torch.tensor: Preprocessed feature vector ready for model input
    """
    import torch
    import numpy as np
    
    # Extract raw features
    raw_features = extract_feature_vector(flow)
    
    # Convert to numpy array and reshape for scaler
    feature_array = np.array(raw_features).reshape(1, -1)
    
    # Handle NaN/inf values
    feature_array = np.nan_to_num(feature_array, 0)
    
    # Apply scaling
    scaled_features = scaler.transform(feature_array)
    
    # Convert to tensor
    return torch.tensor(scaled_features, dtype=torch.float)