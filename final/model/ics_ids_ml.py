import json
import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.contrib.modbus import ModbusADU, ModbusPDUReadCoilsRequest, ModbusPDUWriteSingleRegisterRequest
from scapy.contrib.dnp3 import DNP3, DNP3ApplicationLayer

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

# --- UTILITY FUNCTIONS ---

def create_directories():
    """Ensures the results directory exists."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"Results directory '{RESULTS_DIR}' ensured.")

def extract_modbus_features(pkt, features):
    """Extracts Modbus-specific features from a packet."""
    if ModbusADU in pkt:
        features['is_modbus'] = 1
        
        # Modbus Function Code (Crucial for detecting certain attacks)
        try:
            features['mb_func_code'] = pkt[ModbusADU].unit_id
            
            pdu = pkt.getlayer(1) # ModbusPDU is the layer after ModbusADU
            if hasattr(pdu, 'func_code'):
                features['mb_func_code'] = pdu.func_code
            else:
                features['mb_func_code'] = -1
                
            # Common Request/Response Type Check
            features['mb_read_coils'] = 1 if ModbusPDUReadCoilsRequest in pkt else 0
            features['mb_write_reg'] = 1 if ModbusPDUWriteSingleRegisterRequest in pkt else 0
            
        except AttributeError:
            features['mb_func_code'] = -1
            features['mb_read_coils'] = 0
            features['mb_write_reg'] = 0
    else:
        features.update({'is_modbus': 0, 'mb_func_code': -2, 'mb_read_coils': 0, 'mb_write_reg': 0})
    return features

def extract_dnp3_features(pkt, features):
    """Extracts DNP3-specific features from a packet."""
    if DNP3 in pkt:
        features['is_dnp3'] = 1
        
        # DNP3 Function Code (Crucial for P1 attack: Stealth FIC Start)
        try:
            app_layer = pkt[DNP3ApplicationLayer]
            features['dnp3_func_code'] = app_layer.func
        except:
            features['dnp3_func_code'] = -1
            
        # DNP3 Application Control Field (Sequence and FIN/FIR flags)
        try:
            features['dnp3_app_seq'] = pkt[DNP3ApplicationLayer].seq
            features['dnp3_app_fir'] = pkt[DNP3ApplicationLayer].FIR
            features['dnp3_app_fin'] = pkt[DNP3ApplicationLayer].FIN
        except:
            features['dnp3_app_seq'] = -1
            features['dnp3_app_fir'] = -1
            features['dnp3_app_fin'] = -1
    else:
        features.update({'is_dnp3': 0, 'dnp3_func_code': -2, 'dnp3_app_seq': -1, 'dnp3_app_fir': -1, 'dnp3_app_fin': -1})
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

def load_and_merge_data(protocol):
    """Loads all pcap/json data for a given protocol and merges packet labels."""
    print(f"\n--- Loading {protocol.upper()} Data ---")
    data_frames = []
    
    # Load JSON labels
    label_path = os.path.join(PCAP_DIR, protocol, "pcap_labels.json")
    if not os.path.exists(label_path):
        print(f"Error: Label file not found at {label_path}")
        return pd.DataFrame()
        
    with open(label_path, 'r') as f:
        labels_json = json.load(f)
        
    for filename, data in labels_json.items():
        pcap_path = os.path.join(PCAP_DIR, protocol, filename)
        if not os.path.exists(pcap_path):
            print(f"Warning: PCAP file {pcap_path} not found. Skipping.")
            continue
            
        print(f"Processing {filename}...")
        features_df = extract_packet_features(pcap_path)
        
        # Extract packet labels from JSON
        labels_df = pd.DataFrame(data['packet_labels'])
        labels_df['numeric_label'] = labels_df['label'].map(ATTACK_MAPPING)
        
        # Merge features and labels on packet_number
        merged_df = features_df.merge(labels_df[['packet_number', 'label', 'numeric_label']], 
                                      on='packet_number', how='left')
        merged_df['pcap_file'] = filename
        data_frames.append(merged_df)
        
    return pd.concat(data_frames, ignore_index=True)

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
    report = classification_report(y_test, y_pred, target_names=ATTACK_MAPPING.keys(), output_dict=True)
    
    print(f"Test Accuracy: {accuracy:.4f}")
    
    # Save Classification Report
    report_text = classification_report(y_test, y_pred, target_names=ATTACK_MAPPING.keys())
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
    print(f"\n--- IDS INFERENCE: {pcap_name} ---")
    
    # 1. Extract features and scale
    new_features_df = extract_packet_features(pcap_path)
    
    # Prepare X for prediction (must drop non-feature/target columns)
    # The order of features MUST match the training data!
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
    unique_attacks = sorted(predicted_labels.unique().tolist(), key=lambda x: ATTACK_MAPPING.get(x, 99))
    
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
    print("---------------------------------------")
    print(f"1. Attack Detected (Binary): **{attack_occurred}**")
    print(f"2. Attacks Present (Categories): **{', '.join(unique_attacks)}**")
    print("3. Packet Counts:")
    for label, count in packet_counts.items():
        print(f"   - {label}: {count} packets")
    print(f"4. Temporal Graph saved to: {plot_path}")
    print("---------------------------------------")
    

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    create_directories()

    # 1. Data Loading and Feature Engineering
    all_data = pd.concat([load_and_merge_data("modbus"), load_and_merge_data("dnp3")], ignore_index=True)

    if all_data.empty or 'numeric_label' not in all_data.columns:
        print("\nFATAL ERROR: No data loaded or missing 'numeric_label'. Check PCAP files and JSON labels.")
    else:
        # Separate features (X) and target (y)
        # We must drop the columns that are not features used for training
        EXCLUDED_COLS = ['pcap_file', 'packet_number', 'timestamp', 'label', 'numeric_label']
        X = all_data.drop(columns=EXCLUDED_COLS)
        y = all_data['numeric_label']
        
        # Preserve feature names for inference integrity
        feature_names = X.columns
        
        # Split data for training and testing
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # 2. Scaling (Important for many ML models)
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Convert back to DataFrame for feature name integrity (important for Random Forest)
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_names)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_names)
        
        # 3. Train and Evaluate Model
        model = train_model(X_train_scaled, y_train)
        evaluate_model(model, X_test_scaled, y_test, scaler)

        # 4. Inference on an Unseen PCAP File (Using a random test file for demonstration)
        
        # Select a file from the test set for 'unseen' analysis (or replace with a new pcap)
        test_files = X_test['pcap_file'].unique()
        if len(test_files) > 0:
            unseen_pcap_name = test_files[0]
            # Find the full path of the selected file
            unseen_pcap_path = glob.glob(os.path.join(PCAP_DIR, "**", unseen_pcap_name), recursive=True)[0]
            
            # The scaler and model must be saved and loaded for a true, fresh inference
            # (In this example, we pass the in-memory objects)
            analyze_unseen_pcap(unseen_pcap_path, model, scaler)
        else:
            print("\nCould not find any test PCAP files for inference demonstration.")