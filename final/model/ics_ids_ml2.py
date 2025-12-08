import json
import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import rdpcap, Packet
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

# DNP3 imports - note the underscore in module name
try:
    from scapy.contrib.scapy_dnp3 import DNP3, DNP3ApplicationLayer
    DNP3_AVAILABLE = True
except ImportError:
    print("Warning: DNP3 support not available.")
    DNP3_AVAILABLE = False

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
from joblib import dump, load

# --- CONFIGURATION ---
PCAP_DIR = "pcap"
RESULTS_DIR = "results"
# Labels as required: Normal, P1, P2, P3
ATTACK_MAPPING = {"N": 0, "P1": 1, "P2": 2, "P3": 3}
REVERSE_MAPPING = {v: k for k, v in ATTACK_MAPPING.items()}

# Subdirectories for training data
TRAINING_SUBDIRS = ["modbus", "dnp3"]
# Subdirectory for unseen/test data
UNSEEN_SUBDIR = "unseen"

# --- UTILITY FUNCTIONS ---

def create_directories():
    """Ensures the results directory exists."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"Results directory '{RESULTS_DIR}' ensured.")


def extract_modbus_features(pkt, features):
    """Extracts Modbus-specific features from a packet."""
    if not MODBUS_AVAILABLE:
        features.update({'is_modbus': 0, 'mb_func_code': -2, 'mb_read_coils': 0, 'mb_write_reg': 0})
        return features
    
    # Check for Modbus layers (both request and response)
    has_modbus = (ModbusADURequest in pkt or ModbusADUResponse in pkt)
    
    if has_modbus:
        features['is_modbus'] = 1
        
        try:
            # Try to get the Modbus ADU layer
            modbus_layer = None
            if ModbusADURequest in pkt:
                modbus_layer = pkt[ModbusADURequest]
            elif ModbusADUResponse in pkt:
                modbus_layer = pkt[ModbusADUResponse]
            
            # Extract function code from the payload
            if modbus_layer and hasattr(modbus_layer, 'funcCode'):
                features['mb_func_code'] = modbus_layer.funcCode
            else:
                # Try to get it from the PDU layers
                if ModbusPDU03ReadHoldingRegistersRequest in pkt:
                    features['mb_func_code'] = 3
                elif ModbusPDU06WriteSingleRegisterRequest in pkt:
                    features['mb_func_code'] = 6
                elif ModbusPDU10WriteMultipleRegistersRequest in pkt:
                    features['mb_func_code'] = 16
                else:
                    features['mb_func_code'] = -1
            
            # Check for specific Modbus PDU types
            features['mb_read_coils'] = 1 if ModbusPDU03ReadHoldingRegistersRequest in pkt else 0
            features['mb_write_reg'] = 1 if ModbusPDU06WriteSingleRegisterRequest in pkt else 0
            
        except (AttributeError, IndexError) as e:
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
    
    if DNP3 in pkt:
        features['is_dnp3'] = 1
        
        try:
            # Check if DNP3 Application Layer exists
            if DNP3ApplicationLayer in pkt:
                app_layer = pkt[DNP3ApplicationLayer]
                
                # Extract function code
                if hasattr(app_layer, 'function_code'):
                    features['dnp3_func_code'] = app_layer.function_code
                else:
                    features['dnp3_func_code'] = -1
                
                # Extract application control fields
                if hasattr(app_layer, 'sequence'):
                    features['dnp3_app_seq'] = app_layer.sequence
                else:
                    features['dnp3_app_seq'] = -1
                
                if hasattr(app_layer, 'fir'):
                    features['dnp3_app_fir'] = int(app_layer.fir)
                else:
                    features['dnp3_app_fir'] = -1
                
                if hasattr(app_layer, 'fin'):
                    features['dnp3_app_fin'] = int(app_layer.fin)
                else:
                    features['dnp3_app_fin'] = -1
            else:
                features['dnp3_func_code'] = -1
                features['dnp3_app_seq'] = -1
                features['dnp3_app_fir'] = -1
                features['dnp3_app_fin'] = -1
                
        except (AttributeError, IndexError) as e:
            features['dnp3_func_code'] = -1
            features['dnp3_app_seq'] = -1
            features['dnp3_app_fir'] = -1
            features['dnp3_app_fin'] = -1
    else:
        features.update({'is_dnp3': 0, 'dnp3_func_code': -2, 'dnp3_app_seq': -1, 
                        'dnp3_app_fir': -1, 'dnp3_app_fin': -1})
    
    return features


def extract_packet_features(pcap_file_path):
    """
    Parses a pcap file and extracts features per packet.
    Packet-level features are essential for temporal analysis.
    """
    packets = rdpcap(pcap_file_path)
    features_list = []
    
    for i, pkt in enumerate(packets):
        features = {
            'packet_number': i + 1,
            'timestamp': float(pkt.time),
            'packet_size': len(pkt),
            'ip_len': len(pkt[IP]) if IP in pkt else 0,
            'src_port': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'dst_port': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'is_tcp': 1 if TCP in pkt else 0,
            'is_udp': 1 if UDP in pkt else 0,
        }
        
        # Protocol-Specific Feature Extraction
        features = extract_modbus_features(pkt, features)
        features = extract_dnp3_features(pkt, features)
        
        features_list.append(features)
        
    return pd.DataFrame(features_list)


def load_protocol_data(protocol_dir):
    """
    Loads all pcap and label files from a specific protocol directory.
    Expects JSON label files matching pattern: pcap_labels*.json or *_labels.json
    """
    protocol_name = os.path.basename(protocol_dir)
    print(f"\n--- Loading {protocol_name.upper()} Data ---")
    data_frames = []
    
    if not os.path.exists(protocol_dir):
        print(f"Warning: Directory {protocol_dir} does not exist. Skipping.")
        return pd.DataFrame()
    
    # Look for label files (support multiple naming patterns)
    label_patterns = [
        os.path.join(protocol_dir, "pcap_labels*.json"),
        os.path.join(protocol_dir, "*_labels.json")
    ]
    
    label_files = []
    for pattern in label_patterns:
        label_files.extend(glob.glob(pattern))
    
    # Remove duplicates
    label_files = list(set(label_files))
    
    if not label_files:
        print(f"Error: No label files found in {protocol_dir}")
        print(f"  Looking for files matching: pcap_labels*.json or *_labels.json")
        return pd.DataFrame()
    
    print(f"Found {len(label_files)} label file(s)")
    
    for label_path in label_files:
        print(f"\n  Processing label file: {os.path.basename(label_path)}")
        
        try:
            with open(label_path, 'r') as f:
                labels_json = json.load(f)
            
            # Handle both possible JSON structures:
            # 1. {"pcap_file.pcap": {"packet_labels": [...]}}  (main.py format)
            # 2. {"packet_labels": [...]}  (direct format)
            
            if "packet_labels" in labels_json:
                # Direct format - need to find corresponding pcap
                pcap_files = glob.glob(os.path.join(protocol_dir, "*.pcap"))
                if not pcap_files:
                    print(f"    Warning: No pcap files found in {protocol_dir}")
                    continue
                
                # Use the first pcap file (or match by name pattern)
                pcap_path = pcap_files[0]
                pcap_data = {os.path.basename(pcap_path): labels_json}
            else:
                # main.py format - nested structure
                pcap_data = labels_json
            
            # Process each pcap file referenced in the JSON
            for pcap_filename, data in pcap_data.items():
                # Try to find the pcap file
                pcap_path = os.path.join(protocol_dir, pcap_filename)
                
                if not os.path.exists(pcap_path):
                    print(f"    Warning: PCAP file {pcap_filename} not found in {protocol_dir}. Skipping.")
                    continue
                
                print(f"    Processing PCAP: {pcap_filename}")
                
                # Extract features from pcap
                features_df = extract_packet_features(pcap_path)
                print(f"      Extracted {len(features_df)} packets")
                
                # Extract labels from JSON
                packet_labels = data.get('packet_labels', [])
                if not packet_labels:
                    print(f"      Warning: No packet labels found for {pcap_filename}")
                    continue
                
                labels_df = pd.DataFrame(packet_labels)
                
                # Map labels to numeric values
                labels_df['numeric_label'] = labels_df['label'].map(ATTACK_MAPPING)
                
                # Check for unmapped labels
                unmapped = labels_df['numeric_label'].isna().sum()
                if unmapped > 0:
                    print(f"      Warning: {unmapped} labels could not be mapped to numeric values")
                    print(f"      Unique labels found: {labels_df['label'].unique().tolist()}")
                
                # Merge features and labels on packet_number
                merged_df = features_df.merge(
                    labels_df[['packet_number', 'label', 'numeric_label']], 
                    on='packet_number', 
                    how='left'
                )
                merged_df['pcap_file'] = pcap_filename
                merged_df['protocol'] = protocol_name
                
                # Check for missing labels
                missing_labels = merged_df['numeric_label'].isna().sum()
                if missing_labels > 0:
                    print(f"      Warning: {missing_labels} packets without labels")
                
                data_frames.append(merged_df)
                print(f"      Successfully merged {len(merged_df)} packets")
                
        except Exception as e:
            print(f"    Error processing {label_path}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    if not data_frames:
        return pd.DataFrame()
    
    result = pd.concat(data_frames, ignore_index=True)
    print(f"\n  Total from {protocol_name}: {len(result)} packets")
    return result


def load_all_training_data():
    """
    Loads training data from all protocol subdirectories.
    """
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
        print("\n\u26a0\ufe0f  No training data loaded from any protocol directory!")
        return pd.DataFrame()
    
    combined = pd.concat(all_data, ignore_index=True)
    print("\n" + "="*60)
    print(f"TOTAL TRAINING DATA: {len(combined)} packets")
    print("="*60)
    
    return combined


def train_model(X_train, y_train):
    """Trains the Random Forest model and saves it."""
    print("\n--- Training Random Forest Classifier ---")
    model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    model_path = os.path.join(RESULTS_DIR, "ids_random_forest_model.joblib")
    dump(model, model_path)
    print(f"Model saved to {model_path}")
    return model


def evaluate_model(model, X_test, y_test, scaler):
    """Evaluates the model on the test set and generates evaluation plots."""
    print("\n--- Model Evaluation ---")
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Test Accuracy: {accuracy:.4f}")
    
    # Save Classification Report
    report_text = classification_report(y_test, y_pred, target_names=ATTACK_MAPPING.keys())
    print("\n" + report_text)
    
    with open(os.path.join(RESULTS_DIR, "classification_report.txt"), "w") as f:
        f.write(report_text)
    print("Classification report saved.")
    
    # Save Confusion Matrix Plot
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=ATTACK_MAPPING.keys(), yticklabels=ATTACK_MAPPING.keys())
    plt.title('Confusion Matrix: Packet-Level Classification')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    cm_path = os.path.join(RESULTS_DIR, "confusion_matrix.png")
    plt.savefig(cm_path)
    plt.close()
    print(f"Confusion Matrix saved to {cm_path}")
    

def analyze_unseen_pcap(pcap_path, model, scaler):
    """
    Performs inference on a new pcap file and generates required outputs.
    """
    pcap_name = os.path.basename(pcap_path)
    print(f"\n{'='*60}")
    print(f"IDS INFERENCE: {pcap_name}")
    print(f"{'='*60}")
    
    # 1. Extract features and scale
    new_features_df = extract_packet_features(pcap_path)
    print(f"Extracted {len(new_features_df)} packets from {pcap_name}")
    
    # Prepare X for prediction (must drop non-feature/target columns)
    X_new = new_features_df.drop(columns=['packet_number', 'timestamp'])
    
    # Scale the new features
    X_new_scaled = scaler.transform(X_new)
    
    # 2. Predict packet labels
    predictions = model.predict(X_new_scaled)
    predicted_labels = pd.Series(predictions).map(REVERSE_MAPPING)
    
    # Combine timestamps and predictions
    results_df = pd.DataFrame({
        'timestamp': new_features_df['timestamp'],
        'prediction': predicted_labels
    })

    # --- Task 1: Binary Attack Detection (0 or 1) ---
    is_normal_only = (predicted_labels == 'N').all()
    attack_occurred = 0 if is_normal_only else 1
    
    # --- Task 2: Which Attacks Occurred (Multiclass) ---
    unique_attacks = sorted(predicted_labels.unique().tolist(), 
                           key=lambda x: ATTACK_MAPPING.get(x, 99))
    
    # --- Task 3: Packet Count Per Category ---
    packet_counts = predicted_labels.value_counts().to_dict()
    
    # --- Task 4: Temporal Analysis (Time Window Graph) ---
    plt.figure(figsize=(15, 6))
    
    # Assign numerical position for plotting categories
    plot_y = results_df['prediction'].apply(lambda x: ATTACK_MAPPING[x])
    
    # Plotting the time points for each predicted category
    scatter = plt.scatter(results_df['timestamp'], plot_y, c=plot_y, 
                          cmap='Set1', s=20, alpha=0.8)

    # Create legend and map y-axis ticks
    handles, labels = scatter.legend_elements(num=len(ATTACK_MAPPING))
    plt.legend(handles, ATTACK_MAPPING.keys(), title="Category", loc="upper right")
    
    plt.yticks(list(ATTACK_MAPPING.values()), list(ATTACK_MAPPING.keys()))
    plt.xlabel("Time (seconds)")
    plt.ylabel("Attack Category")
    plt.title(f"Temporal IDS Analysis for {pcap_name}")
    plt.grid(axis='y', linestyle='--')
    
    plot_path = os.path.join(RESULTS_DIR, f"{pcap_name}_temporal_analysis.png")
    plt.savefig(plot_path)
    plt.close()
    
    # --- Output Results ---
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


def analyze_unseen_directory():
    """
    Analyzes all pcap files in the unseen directory.
    """
    unseen_dir = os.path.join(PCAP_DIR, UNSEEN_SUBDIR)
    
    if not os.path.exists(unseen_dir):
        print(f"\n\u26a0\ufe0f  Unseen directory '{unseen_dir}' does not exist. Skipping inference.")
        return
    
    # Find all pcap files in unseen directory
    unseen_pcaps = glob.glob(os.path.join(unseen_dir, "*.pcap"))
    
    if not unseen_pcaps:
        print(f"\n\u26a0\ufe0f  No pcap files found in '{unseen_dir}'. Skipping inference.")
        return
    
    print(f"\n{'='*60}")
    print(f"ANALYZING UNSEEN DATA")
    print(f"Found {len(unseen_pcaps)} pcap file(s) in {unseen_dir}")
    print(f"{'='*60}")
    
    # Load trained model and scaler
    model_path = os.path.join(RESULTS_DIR, "ids_random_forest_model.joblib")
    scaler_path = os.path.join(RESULTS_DIR, "scaler.joblib")
    
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("\n\u26a0\ufe0f  Model or scaler not found. Please train the model first.")
        return
    
    model = load(model_path)
    scaler = load(scaler_path)
    print(f"Loaded model from {model_path}")
    print(f"Loaded scaler from {scaler_path}")
    
    # Analyze each unseen pcap
    for pcap_path in sorted(unseen_pcaps):
        try:
            analyze_unseen_pcap(pcap_path, model, scaler)
        except Exception as e:
            print(f"\n\u26a0\ufe0f  Error analyzing {os.path.basename(pcap_path)}: {e}")
            import traceback
            traceback.print_exc()
            continue


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    create_directories()

    # 1. Data Loading and Feature Engineering
    all_data = load_all_training_data()

    if all_data.empty or 'numeric_label' not in all_data.columns:
        print("\n\u274c FATAL ERROR: No data loaded or missing 'numeric_label'.")
        print("\nExpected directory structure:")
        print(f"  {PCAP_DIR}/")
        print(f"    modbus/")
        print(f"      *.pcap")
        print(f"      pcap_labels*.json")
        print(f"    dnp3/")
        print(f"      *.pcap")
        print(f"      pcap_labels*.json")
        print(f"    unseen/")
        print(f"      *.pcap")
    else:
        # Remove rows with missing labels
        before_count = len(all_data)
        all_data = all_data.dropna(subset=['numeric_label'])
        after_count = len(all_data)
        
        if before_count > after_count:
            print(f"\n\u26a0\ufe0f  Dropped {before_count - after_count} packets with missing labels")
        
        print(f"\n\u2713 Training with {len(all_data)} labeled packets")
        
        # Show label distribution
        print("\nLabel Distribution:")
        for label, count in all_data['label'].value_counts().sort_index().items():
            percentage = (count / len(all_data)) * 100
            print(f"  {label}: {count} packets ({percentage:.1f}%)")
        
        # Separate features (X) and target (y)
        EXCLUDED_COLS = ['pcap_file', 'protocol', 'packet_number', 'timestamp', 'label', 'numeric_label']
        X = all_data.drop(columns=EXCLUDED_COLS)
        y = all_data['numeric_label']
        
        # Preserve feature names for inference integrity
        feature_names = X.columns
        print(f"\nFeatures used for training ({len(feature_names)}): {list(feature_names)}")
        
        # Split data for training and testing
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"\nTrain set: {len(X_train)} packets")
        print(f"Test set: {len(X_test)} packets")
        
        # 2. Scaling (Important for many ML models)
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Save the scaler for later use
        scaler_path = os.path.join(RESULTS_DIR, "scaler.joblib")
        dump(scaler, scaler_path)
        print(f"Scaler saved to {scaler_path}")
        
        # Convert back to DataFrame for feature name integrity
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_names)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_names)
        
        # 3. Train and Evaluate Model
        model = train_model(X_train_scaled, y_train)
        evaluate_model(model, X_test_scaled, y_test, scaler)
        
        print("\n\u2713 Training and evaluation complete!")

        # 4. Analyze all unseen pcap files
        analyze_unseen_directory()