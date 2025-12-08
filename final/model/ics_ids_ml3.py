import json
import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP

# Modbus imports - corrected layer names
try:
    from scapy.all import load_contrib
    load_contrib('modbus')
    from scapy.contrib.modbus import (
        ModbusADURequest, 
        ModbusADUResponse,
        ModbusPDU03ReadHoldingRegistersRequest,
        ModbusPDU06WriteSingleRegisterRequest,
        ModbusPDU10WriteMultipleRegistersRequest
    )
    MODBUS_AVAILABLE = True
except ImportError:
    print("Warning: Modbus support not available. Install with: pip install scapy")
    MODBUS_AVAILABLE = False

# DNP3 imports
DNP3_AVAILABLE = False

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from joblib import dump, load
import warnings
warnings.filterwarnings('ignore')

# --- CONFIGURATION ---
PCAP_DIR = "pcap"
RESULTS_DIR = "results"
ATTACK_MAPPING = {"N": 0, "P1": 1, "P2": 2, "P3": 3}
REVERSE_MAPPING = {v: k for k, v in ATTACK_MAPPING.items()}

TRAINING_SUBDIRS = ["modbus", "dnp3"]
UNSEEN_SUBDIR = "unseen"

# --- UTILITY FUNCTIONS ---

def create_directories():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"Results directory '{RESULTS_DIR}' ensured.")


def extract_modbus_features(pkt, features):
    """Extracts Modbus-specific features from a packet."""
    if not MODBUS_AVAILABLE:
        features.update({'is_modbus': 0, 'mb_func_code': -2, 'mb_read_coils': 0, 'mb_write_reg': 0})
        return features
    
    has_modbus = (ModbusADURequest in pkt or ModbusADUResponse in pkt)
    
    if has_modbus:
        features['is_modbus'] = 1
        
        try:
            modbus_layer = None
            if ModbusADURequest in pkt:
                modbus_layer = pkt[ModbusADURequest]
            elif ModbusADUResponse in pkt:
                modbus_layer = pkt[ModbusADUResponse]
            
            if modbus_layer and hasattr(modbus_layer, 'funcCode'):
                features['mb_func_code'] = modbus_layer.funcCode
            else:
                if ModbusPDU03ReadHoldingRegistersRequest in pkt:
                    features['mb_func_code'] = 3
                elif ModbusPDU06WriteSingleRegisterRequest in pkt:
                    features['mb_func_code'] = 6
                elif ModbusPDU10WriteMultipleRegistersRequest in pkt:
                    features['mb_func_code'] = 16
                else:
                    features['mb_func_code'] = -1
            
            features['mb_read_coils'] = 1 if ModbusPDU03ReadHoldingRegistersRequest in pkt else 0
            features['mb_write_reg'] = 1 if ModbusPDU06WriteSingleRegisterRequest in pkt else 0
            
        except (AttributeError, IndexError):
            features['mb_func_code'] = -1
            features['mb_read_coils'] = 0
            features['mb_write_reg'] = 0
    else:
        features.update({'is_modbus': 0, 'mb_func_code': -2, 'mb_read_coils': 0, 'mb_write_reg': 0})
    
    return features


def extract_dnp3_features(pkt, features):
    """Extracts DNP3-specific features from a packet."""
    if not DNP3_AVAILABLE:
        features.update({'is_dnp3': 0, 'dnp3_func_code': -2, 'dnp3_app_seq': -1, 
                        'dnp3_app_fir': -1, 'dnp3_app_fin': -1})
        return features


def extract_packet_features(pcap_file_path):
    """Parses a pcap file and extracts features per packet."""
    packets = rdpcap(pcap_file_path)
    features_list = []
    
    prev_time = None
    for i, pkt in enumerate(packets):
        current_time = float(pkt.time)
        
        features = {
            'packet_number': i + 1,
            'timestamp': current_time,
            'packet_size': len(pkt),
            'ip_len': len(pkt[IP]) if IP in pkt else 0,
            'src_port': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'dst_port': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'is_tcp': 1 if TCP in pkt else 0,
            'is_udp': 1 if UDP in pkt else 0,
            # Inter-arrival time (important for detecting flooding attacks)
            'inter_arrival_time': current_time - prev_time if prev_time is not None else 0.0
        }
        
        # Protocol-Specific Feature Extraction
        features = extract_modbus_features(pkt, features)
        features = extract_dnp3_features(pkt, features)
        
        features_list.append(features)
        prev_time = current_time
        
    return pd.DataFrame(features_list)


def load_protocol_data(protocol_dir):
    """Loads all pcap and label files from a specific protocol directory."""
    protocol_name = os.path.basename(protocol_dir)
    print(f"\n--- Loading {protocol_name.upper()} Data ---")
    data_frames = []
    
    if not os.path.exists(protocol_dir):
        print(f"Warning: Directory {protocol_dir} does not exist. Skipping.")
        return pd.DataFrame()
    
    label_patterns = [
        os.path.join(protocol_dir, "pcap_labels*.json"),
        os.path.join(protocol_dir, "*_labels.json")
    ]
    
    label_files = []
    for pattern in label_patterns:
        label_files.extend(glob.glob(pattern))
    
    label_files = list(set(label_files))
    
    if not label_files:
        print(f"Error: No label files found in {protocol_dir}")
        return pd.DataFrame()
    
    print(f"Found {len(label_files)} label file(s)")
    
    for label_path in label_files:
        try:
            with open(label_path, 'r') as f:
                labels_json = json.load(f)
            
            if "packet_labels" in labels_json:
                pcap_files = glob.glob(os.path.join(protocol_dir, "*.pcap"))
                if not pcap_files:
                    continue
                pcap_path = pcap_files[0]
                pcap_data = {os.path.basename(pcap_path): labels_json}
            else:
                pcap_data = labels_json
            
            for pcap_filename, data in pcap_data.items():
                pcap_path = os.path.join(protocol_dir, pcap_filename)
                
                if not os.path.exists(pcap_path):
                    continue
                
                features_df = extract_packet_features(pcap_path)
                packet_labels = data.get('packet_labels', [])
                
                if not packet_labels:
                    continue
                
                labels_df = pd.DataFrame(packet_labels)
                labels_df['numeric_label'] = labels_df['label'].map(ATTACK_MAPPING)
                
                merged_df = features_df.merge(
                    labels_df[['packet_number', 'label', 'numeric_label']], 
                    on='packet_number', 
                    how='left'
                )
                merged_df['pcap_file'] = pcap_filename
                merged_df['protocol'] = protocol_name
                
                data_frames.append(merged_df)
                
        except Exception as e:
            print(f"    Error processing {label_path}: {e}")
            continue
    
    if not data_frames:
        return pd.DataFrame()
    
    result = pd.concat(data_frames, ignore_index=True)
    print(f"  Total from {protocol_name}: {len(result)} packets")
    return result


def load_all_training_data():
    """Loads training data from all protocol subdirectories."""
    print("\n" + "="*60)
    print("LOADING TRAINING DATA")
    print("="*60)
    
    all_data = []
    
    for subdir in TRAINING_SUBDIRS:
        protocol_dir = os.path.join(PCAP_DIR, subdir)
        protocol_data = load_protocol_data(protocol_dir)
        
        if not protocol_data.empty:
            all_data.append(protocol_data)
    
    if not all_data:
        print("\n⚠️  No training data loaded!")
        return pd.DataFrame()
    
    combined = pd.concat(all_data, ignore_index=True)
    print("\n" + "="*60)
    print(f"TOTAL TRAINING DATA: {len(combined)} packets")
    print("="*60)
    
    return combined


def train_model(X_train, y_train):
    """Trains the Random Forest model with class weights."""
    print("\n--- Training Random Forest Classifier ---")
    
    # Compute class weights to handle imbalance
    class_weights = compute_class_weight('balanced', 
                                         classes=np.unique(y_train), 
                                         y=y_train)
    class_weight_dict = dict(zip(np.unique(y_train), class_weights))
    
    print(f"Class weights computed: {class_weight_dict}")
    
    # Increased complexity for better learning
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight=class_weight_dict,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    model.fit(X_train, y_train)
    
    model_path = os.path.join(RESULTS_DIR, "ids_random_forest_model.joblib")
    dump(model, model_path)
    print(f"Model saved to {model_path}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10).to_string(index=False))
    
    return model


def evaluate_model(model, X_test, y_test, scaler):
    """Evaluates the model on the test set."""
    print("\n--- Model Evaluation ---")
    
    # Keep as numpy array to avoid feature name warnings
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    
    # Detailed per-class metrics
    report_text = classification_report(y_test, y_pred, 
                                       target_names=ATTACK_MAPPING.keys(),
                                       zero_division=0)
    print("\n" + report_text)
    
    with open(os.path.join(RESULTS_DIR, "classification_report.txt"), "w") as f:
        f.write(report_text)
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=ATTACK_MAPPING.keys(), 
                yticklabels=ATTACK_MAPPING.keys(),
                cbar_kws={'label': 'Count'})
    plt.title('Confusion Matrix: Packet-Level Classification', fontsize=14, pad=20)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    
    cm_path = os.path.join(RESULTS_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"\nConfusion Matrix saved to {cm_path}")
    
    # Per-class accuracy
    print("\nPer-Class Accuracy:")
    for i, label in enumerate(ATTACK_MAPPING.keys()):
        mask = y_test == i
        if mask.sum() > 0:
            class_acc = (y_pred[mask] == i).sum() / mask.sum()
            print(f"  {label}: {class_acc:.4f} ({mask.sum()} samples)")


def analyze_unseen_pcap(pcap_path, model, scaler, feature_names):
    """Performs inference on a new pcap file."""
    pcap_name = os.path.basename(pcap_path)
    print(f"\n{'='*60}")
    print(f"IDS INFERENCE: {pcap_name}")
    print(f"{'='*60}")
    
    # Extract features
    new_features_df = extract_packet_features(pcap_path)
    print(f"Extracted {len(new_features_df)} packets from {pcap_name}")
    
    # Prepare X for prediction
    X_new = new_features_df.drop(columns=['packet_number', 'timestamp'])
    
    # Ensure feature order matches training
    X_new = X_new[feature_names]
    
    # Scale and predict
    X_new_scaled = scaler.transform(X_new)
    predictions = model.predict(X_new_scaled)
    predicted_labels = pd.Series(predictions).map(REVERSE_MAPPING)
    
    results_df = pd.DataFrame({
        'timestamp': new_features_df['timestamp'],
        'prediction': predicted_labels
    })

    # Analysis
    is_normal_only = (predicted_labels == 'N').all()
    attack_occurred = 0 if is_normal_only else 1
    
    unique_attacks = sorted(predicted_labels.unique().tolist(), 
                           key=lambda x: ATTACK_MAPPING.get(x, 99))
    
    packet_counts = predicted_labels.value_counts().to_dict()
    
    # Temporal Analysis Plot
    plt.figure(figsize=(15, 6))
    
    plot_y = results_df['prediction'].apply(lambda x: ATTACK_MAPPING[x])
    
    scatter = plt.scatter(results_df['timestamp'], plot_y, c=plot_y, 
                          cmap='Set1', s=30, alpha=0.7, edgecolors='black', linewidth=0.5)

    handles, labels = scatter.legend_elements(num=len(ATTACK_MAPPING))
    plt.legend(handles, ATTACK_MAPPING.keys(), title="Category", 
               loc="upper right", framealpha=0.9)
    
    plt.yticks(list(ATTACK_MAPPING.values()), list(ATTACK_MAPPING.keys()))
    plt.xlabel("Time (seconds)", fontsize=12)
    plt.ylabel("Attack Category", fontsize=12)
    plt.title(f"Temporal IDS Analysis for {pcap_name}", fontsize=14, pad=20)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plot_path = os.path.join(RESULTS_DIR, f"{pcap_name}_temporal_analysis.png")
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    # Output Results
    print("\n" + "-"*60)
    print("ANALYSIS RESULTS")
    print("-"*60)
    print(f"1. Attack Detected (Binary): {attack_occurred}")
    print(f"2. Attacks Present (Categories): {', '.join(unique_attacks)}")
    print(f"3. Packet Counts:")
    for label in sorted(packet_counts.keys(), key=lambda x: ATTACK_MAPPING.get(x, 99)):
        count = packet_counts[label]
        percentage = (count / len(predicted_labels)) * 100
        print(f"   - {label}: {count} packets ({percentage:.1f}%)")
    print(f"4. Temporal Graph saved to: {plot_path}")
    print("-"*60 + "\n")


def analyze_unseen_directory(feature_names):
    """Analyzes all pcap files in the unseen directory."""
    unseen_dir = os.path.join(PCAP_DIR, UNSEEN_SUBDIR)
    
    if not os.path.exists(unseen_dir):
        print(f"\n⚠️  Unseen directory '{unseen_dir}' does not exist. Skipping inference.")
        return
    
    unseen_pcaps = glob.glob(os.path.join(unseen_dir, "*.pcap"))
    
    if not unseen_pcaps:
        print(f"\n⚠️  No pcap files found in '{unseen_dir}'. Skipping inference.")
        return
    
    print(f"\n{'='*60}")
    print(f"ANALYZING UNSEEN DATA")
    print(f"Found {len(unseen_pcaps)} pcap file(s) in {unseen_dir}")
    print(f"{'='*60}")
    
    model_path = os.path.join(RESULTS_DIR, "ids_random_forest_model.joblib")
    scaler_path = os.path.join(RESULTS_DIR, "scaler.joblib")
    
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("\n⚠️  Model or scaler not found. Please train the model first.")
        return
    
    model = load(model_path)
    scaler = load(scaler_path)
    print(f"Loaded model from {model_path}")
    print(f"Loaded scaler from {scaler_path}")
    
    for pcap_path in sorted(unseen_pcaps):
        try:
            analyze_unseen_pcap(pcap_path, model, scaler, feature_names)
        except Exception as e:
            print(f"\n⚠️  Error analyzing {os.path.basename(pcap_path)}: {e}")
            import traceback
            traceback.print_exc()


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    create_directories()

    all_data = load_all_training_data()

    if all_data.empty or 'numeric_label' not in all_data.columns:
        print("\n❌ FATAL ERROR: No data loaded or missing 'numeric_label'.")
    else:
        # Clean data
        all_data = all_data.dropna(subset=['numeric_label'])
        print(f"\n✓ Training with {len(all_data)} labeled packets")
        
        # Show label distribution
        print("\nLabel Distribution:")
        for label in sorted(ATTACK_MAPPING.keys(), key=lambda x: ATTACK_MAPPING[x]):
            count = (all_data['label'] == label).sum()
            percentage = (count / len(all_data)) * 100
            print(f"  {label}: {count} packets ({percentage:.1f}%)")
        
        # Prepare features
        EXCLUDED_COLS = ['pcap_file', 'protocol', 'packet_number', 'timestamp', 'label', 'numeric_label']
        X = all_data.drop(columns=EXCLUDED_COLS)
        y = all_data['numeric_label']
        
        feature_names = X.columns.tolist()
        print(f"\nFeatures ({len(feature_names)}): {feature_names}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"\nTrain set: {len(X_train)} packets")
        print(f"Test set: {len(X_test)} packets")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Keep feature names for later use
        X_train_df = pd.DataFrame(X_train_scaled, columns=feature_names)
        
        scaler_path = os.path.join(RESULTS_DIR, "scaler.joblib")
        dump(scaler, scaler_path)
        
        # Save feature names
        feature_names_path = os.path.join(RESULTS_DIR, "feature_names.json")
        with open(feature_names_path, 'w') as f:
            json.dump(feature_names, f)
        
        # Train and evaluate
        model = train_model(X_train_df, y_train)
        evaluate_model(model, X_test, y_test, scaler)
        
        print("\n✓ Training and evaluation complete!")

        # Analyze unseen data
        analyze_unseen_directory(feature_names)