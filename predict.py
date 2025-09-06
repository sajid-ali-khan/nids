import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
import numpy as np
from sklearn.neighbors import kneighbors_graph
from scapy.all import sniff
import pickle
import os

# Your GCN model class (must match the training code)
class GCN(torch.nn.Module):
    def __init__(self, in_feats, hid_feats, num_classes):
        super().__init__()
        self.conv1 = GCNConv(in_feats, hid_feats)
        self.conv2 = GCNConv(hid_feats, hid_feats)
        self.lin = torch.nn.Linear(hid_feats, num_classes)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.relu(self.conv2(x, edge_index))
        return F.log_softmax(self.lin(x), dim=1)

def load_model():
    """Load the trained GCN model"""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    try:
        # Load the model
        model_path = './model/gnn_nids_model.pth'
        checkpoint = torch.load(model_path, map_location=device)
        
        # Initialize model with same parameters as training
        # CICIDS-2017 has 78 features, 5 classes after merging
        model = GCN(in_feats=78, hid_feats=64, num_classes=5).to(device)
        
        if isinstance(checkpoint, dict) and 'model_state_dict' in checkpoint:
            model.load_state_dict(checkpoint['model_state_dict'])
        else:
            model.load_state_dict(checkpoint)
            
        model.eval()
        print(f"✅ Model loaded successfully from {model_path}")
        return model, device
        
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return None, None

def load_scaler():
    """Try to load the scaler - you might need to save this from your training script"""
    try:
        with open('./model/scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        print("✅ Scaler loaded successfully")
        return scaler
    except:
        print("⚠️ Scaler not found. You'll need to create/save it from your training script.")
        print("   Add this to your training script after creating the scaler:")
        print("   import pickle")
        print("   with open('./model/scaler.pkl', 'wb') as f:")
        print("       pickle.dump(scaler, f)")
        return None

def predict_single_flow(model, device, flow_features, scaler=None):
    """Predict a single flow"""
    # Prepare features
    features = np.array(flow_features).reshape(1, -1)
    features = np.nan_to_num(features, 0)  # Handle NaN/inf
    
    if scaler:
        features = scaler.transform(features)
    
    # Create simple graph with single node (no edges needed for single prediction)
    x = torch.tensor(features, dtype=torch.float).to(device)
    edge_index = torch.empty((2, 0), dtype=torch.long).to(device)
    
    # Make prediction
    with torch.no_grad():
        logits = model(x, edge_index)
        probabilities = torch.exp(logits)
        prediction = logits.argmax(dim=1).cpu().item()
        confidence = probabilities.max(dim=1)[0].cpu().item()
    
    return prediction, confidence

def predict_multiple_flows(model, device, flows_dict, scaler=None):
    """Predict multiple flows using graph structure"""
    if not flows_dict:
        return []
    
    # Extract features for all flows
    flow_features = []
    flow_keys = list(flows_dict.keys())
    
    for flow in flows_dict.values():
        features = extract_feature_vector(flow)
        flow_features.append(features)
    
    # Prepare feature matrix
    X = np.array(flow_features)
    X = np.nan_to_num(X, 0)
    
    if scaler:
        X = scaler.transform(X)
    
    # Create k-NN graph for multiple flows
    if len(flows_dict) > 1:
        k = min(5, len(flows_dict) - 1)
        A = kneighbors_graph(X, n_neighbors=k, mode='connectivity', include_self=False).tocoo()
        edge_index = torch.from_numpy(np.vstack((A.row, A.col)).astype(np.int64)).to(device)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long).to(device)
    
    # Create graph data
    x = torch.tensor(X, dtype=torch.float).to(device)
    
    # Make predictions
    with torch.no_grad():
        logits = model(x, edge_index)
        probabilities = torch.exp(logits)
        predictions = logits.argmax(dim=1).cpu().numpy()
        confidences = probabilities.max(dim=1)[0].cpu().numpy()
    
    # Map predictions to class names
    class_names = ['BENIGN', 'DDoS', 'DoS', 'Other', 'PortScan']
    
    results = []
    for i, (flow_key, pred, conf) in enumerate(zip(flow_keys, predictions, confidences)):
        results.append({
            'flow_key': flow_key,
            'prediction': class_names[pred],
            'confidence': conf,
            'flow_info': {
                'fwd_packets': flows_dict[flow_key]['fwd_packets'],
                'bwd_packets': flows_dict[flow_key]['bwd_packets'],
                'total_bytes': flows_dict[flow_key]['fwd_bytes'] + flows_dict[flow_key]['bwd_bytes']
            }
        })
    
    return results

# Import your functions (make sure these are available)
try:
    from feature_vector_extractor import extract_feature_vector
    from packet_saver import save_flow
    from flow_model import initialize_flow
except ImportError:
    print("⚠️ Make sure your feature_vector_extractor.py, packet_saver.py, and flow_model.py are available")

def main():
    """Main prediction function"""
    print("🚀 Starting Network Intrusion Detection...")
    
    # Load model
    model, device = load_model()
    if model is None:
        return
    
    # Load scaler (optional but recommended)
    scaler = load_scaler()
    
    print("\n📡 Capturing network traffic for 15 seconds...")
    
    # Capture packets
    flows = {}
    packets = sniff(prn=lambda x: save_flow(flows, x), timeout=15, filter="tcp or udp")
    
    print(f"✅ Captured {len(packets)} packets, created {len(flows)} flows")
    
    if not flows:
        print("❌ No flows captured. Make sure you have network traffic.")
        return
    
    # Make predictions
    print("\n🔮 Making predictions...")
    results = predict_multiple_flows(model, device, flows, scaler)
    
    # Display results
    print("\n" + "="*60)
    print("🛡️  NETWORK INTRUSION DETECTION RESULTS")
    print("="*60)
    
    benign_count = 0
    attack_count = 0
    
    for result in results:
        prediction = result['prediction']
        confidence = result['confidence']
        flow_info = result['flow_info']
        
        if prediction == 'BENIGN':
            benign_count += 1
            status = "✅"
        else:
            attack_count += 1
            status = "🚨"
        
        print(f"{status} {prediction} (Confidence: {confidence:.3f})")
        print(f"   Packets: {flow_info['fwd_packets']}→ {flow_info['bwd_packets']}← | Bytes: {flow_info['total_bytes']:,}")
        print(f"   Flow: {result['flow_key']}")
        print()
    
    print(f"📊 SUMMARY: {benign_count} Benign, {attack_count} Suspicious flows")
    
    if attack_count > 0:
        print(f"⚠️  {attack_count} potentially malicious flows detected!")
    else:
        print("✅ All traffic appears normal.")

if __name__ == "__main__":
    main()