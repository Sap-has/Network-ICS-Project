import json
import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from collections import Counter

# Modbus imports
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

DNP3_AVAILABLE = False

from sklearn.model_selection import train_test_split, learning_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix, accuracy_score,
                            roc_curve, auc)
from sklearn.preprocessing import StandardScaler, label_binarize
from sklearn.utils.class_weight import compute_class_weight
from joblib import dump, load
import warnings
warnings.filterwarnings('ignore')

# Set style for better-looking plots
sns.set_style("whitegrid")
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10

# --- CONFIGURATION ---
PCAP_DIR = "pcap"
RESULTS_DIR = "results"
PLOTS_DIR = os.path.join(RESULTS_DIR, "plots")
ATTACK_MAPPING = {"N": 0, "P1": 1, "P2": 2, "P3": 3}
REVERSE_MAPPING = {v: k for k, v in ATTACK_MAPPING.items()}
TRAINING_SUBDIRS = ["modbus", "dnp3"]
UNSEEN_SUBDIR = "unseen"

# Color scheme for attacks
ATTACK_COLORS = {'N': '#2ecc71', 'P1': '#f39c12', 'P2': '#e74c3c', 'P3': '#8e44ad'}

# --- UTILITY FUNCTIONS ---

def create_directories():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(PLOTS_DIR, exist_ok=True)
    print(f"Results directory '{RESULTS_DIR}' and plots directory '{PLOTS_DIR}' ensured.")


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
            'inter_arrival_time': current_time - prev_time if prev_time is not None else 0.0
        }
        
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
        print("\n\u26a0\ufe0f  No training data loaded!")
        return pd.DataFrame()
    
    combined = pd.concat(all_data, ignore_index=True)
    print("\n" + "="*60)
    print(f"TOTAL TRAINING DATA: {len(combined)} packets")
    print("="*60)
    
    return combined


def plot_class_distribution(all_data):
    """Creates comprehensive class distribution visualizations."""
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Overall distribution
    label_counts = all_data['label'].value_counts()
    label_counts = label_counts.reindex(list(ATTACK_MAPPING.keys()), fill_value=0)
    
    colors = [ATTACK_COLORS[label] for label in label_counts.index]
    axes[0, 0].bar(label_counts.index, label_counts.values, color=colors, edgecolor='black', linewidth=1.5)
    axes[0, 0].set_title('Overall Class Distribution', fontsize=14, fontweight='bold')
    axes[0, 0].set_xlabel('Attack Type', fontsize=12)
    axes[0, 0].set_ylabel('Number of Packets', fontsize=12)
    axes[0, 0].grid(axis='y', alpha=0.3)
    for i, v in enumerate(label_counts.values):
        axes[0, 0].text(i, v + max(label_counts.values)*0.01, str(v), 
                       ha='center', va='bottom', fontweight='bold')
    
    # Per-protocol distribution
    protocol_dist = all_data.groupby(['protocol', 'label']).size().unstack(fill_value=0)
    protocol_dist = protocol_dist.reindex(columns=list(ATTACK_MAPPING.keys()), fill_value=0)
    protocol_dist.plot(kind='bar', stacked=False, ax=axes[0, 1], 
                       color=[ATTACK_COLORS[col] for col in protocol_dist.columns],
                       edgecolor='black', linewidth=1.5)
    axes[0, 1].set_title('Class Distribution by Protocol', fontsize=14, fontweight='bold')
    axes[0, 1].set_xlabel('Protocol', fontsize=12)
    axes[0, 1].set_ylabel('Number of Packets', fontsize=12)
    axes[0, 1].legend(title='Attack Type', bbox_to_anchor=(1.05, 1), loc='upper left')
    axes[0, 1].grid(axis='y', alpha=0.3)
    plt.setp(axes[0, 1].xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    # Percentage distribution pie chart
    percentages = (label_counts / label_counts.sum() * 100)
    axes[1, 0].pie(percentages, labels=percentages.index, autopct='%1.1f%%',
                   colors=colors, startangle=90, textprops={'fontsize': 11, 'fontweight': 'bold'},
                   wedgeprops={'edgecolor': 'black', 'linewidth': 1.5})
    axes[1, 0].set_title('Percentage Distribution of Attack Types', fontsize=14, fontweight='bold')
    
    # Protocol composition
    protocol_counts = all_data['protocol'].value_counts()
    axes[1, 1].pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%',
                   startangle=90, colors=sns.color_palette("Set2", len(protocol_counts)),
                   textprops={'fontsize': 11, 'fontweight': 'bold'},
                   wedgeprops={'edgecolor': 'black', 'linewidth': 1.5})
    axes[1, 1].set_title('Protocol Distribution in Training Data', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "class_distribution_analysis.png"), bbox_inches='tight')
    plt.close()
    print(f"\u2713 Class distribution analysis saved")


def plot_feature_importance(model, feature_names, all_data):
    """Creates detailed feature importance visualizations."""
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Overall feature importance
    fig, axes = plt.subplots(1, 2, figsize=(18, 8))
    
    top_n = min(15, len(feature_importance))
    top_features = feature_importance.head(top_n)
    
    colors_gradient = plt.cm.viridis(np.linspace(0.3, 0.9, top_n))
    axes[0].barh(range(top_n), top_features['importance'].values, color=colors_gradient, edgecolor='black', linewidth=1)
    axes[0].set_yticks(range(top_n))
    axes[0].set_yticklabels(top_features['feature'].values)
    axes[0].invert_yaxis()
    axes[0].set_xlabel('Importance Score', fontsize=12)
    axes[0].set_title(f'Top {top_n} Most Important Features', fontsize=14, fontweight='bold')
    axes[0].grid(axis='x', alpha=0.3)
    
    # Cumulative importance
    cumsum = np.cumsum(feature_importance['importance'].values)
    axes[1].plot(range(1, len(cumsum) + 1), cumsum, marker='o', linewidth=2, markersize=6, color='#e74c3c')
    axes[1].axhline(y=0.95, color='green', linestyle='--', linewidth=2, label='95% Threshold')
    axes[1].fill_between(range(1, len(cumsum) + 1), cumsum, alpha=0.3, color='#e74c3c')
    axes[1].set_xlabel('Number of Features', fontsize=12)
    axes[1].set_ylabel('Cumulative Importance', fontsize=12)
    axes[1].set_title('Cumulative Feature Importance', fontsize=14, fontweight='bold')
    axes[1].legend(fontsize=10)
    axes[1].grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "feature_importance_overall.png"), bbox_inches='tight')
    plt.close()
    print(f"\u2713 Overall feature importance saved")
    
    # Protocol-specific feature importance
    protocol_features = {}
    for protocol in all_data['protocol'].unique():
        protocol_data = all_data[all_data['protocol'] == protocol]
        if len(protocol_data) > 100:  # Only if enough samples
            protocol_features[protocol] = {}
            
            # Get protocol-specific features
            if protocol == 'modbus':
                specific_cols = [col for col in feature_names if 'mb_' in col or 'modbus' in col]
            elif protocol == 'dnp3':
                specific_cols = [col for col in feature_names if 'dnp3' in col]
            else:
                continue
            
            for col in specific_cols:
                if col in feature_names:
                    idx = feature_names.index(col)
                    protocol_features[protocol][col] = model.feature_importances_[idx]
    
    if protocol_features:
        fig, axes = plt.subplots(1, len(protocol_features), figsize=(10*len(protocol_features), 8))
        if len(protocol_features) == 1:
            axes = [axes]
        
        for idx, (protocol, features) in enumerate(protocol_features.items()):
            if features:
                sorted_features = sorted(features.items(), key=lambda x: x[1], reverse=True)
                feat_names, feat_values = zip(*sorted_features)
                
                colors = plt.cm.plasma(np.linspace(0.3, 0.9, len(feat_names)))
                axes[idx].barh(range(len(feat_names)), feat_values, color=colors, edgecolor='black', linewidth=1)
                axes[idx].set_yticks(range(len(feat_names)))
                axes[idx].set_yticklabels(feat_names)
                axes[idx].invert_yaxis()
                axes[idx].set_xlabel('Importance Score', fontsize=12)
                axes[idx].set_title(f'{protocol.upper()}-Specific Feature Importance', 
                                   fontsize=14, fontweight='bold')
                axes[idx].grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(os.path.join(PLOTS_DIR, "feature_importance_by_protocol.png"), bbox_inches='tight')
        plt.close()
        print(f"\u2713 Protocol-specific feature importance saved")


def plot_learning_curves(model, X_train, y_train):
    """Generates learning curves to assess model performance."""
    print("\n--- Generating Learning Curves ---")
    
    train_sizes, train_scores, val_scores = learning_curve(
        model, X_train, y_train, cv=5, n_jobs=-1, 
        train_sizes=np.linspace(0.1, 1.0, 10),
        scoring='accuracy', random_state=42
    )
    
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)
    val_std = np.std(val_scores, axis=1)
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    ax.plot(train_sizes, train_mean, 'o-', color='#3498db', linewidth=2.5, 
            markersize=8, label='Training Score')
    ax.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, 
                     alpha=0.2, color='#3498db')
    
    ax.plot(train_sizes, val_mean, 'o-', color='#e74c3c', linewidth=2.5, 
            markersize=8, label='Validation Score')
    ax.fill_between(train_sizes, val_mean - val_std, val_mean + val_std, 
                     alpha=0.2, color='#e74c3c')
    
    ax.set_xlabel('Training Set Size', fontsize=12, fontweight='bold')
    ax.set_ylabel('Accuracy Score', fontsize=12, fontweight='bold')
    ax.set_title('Learning Curves: Model Performance vs Training Size', 
                fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='lower right', fontsize=11)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "learning_curves.png"), bbox_inches='tight')
    plt.close()
    print(f"\u2713 Learning curves saved")


def plot_roc_curves(model, X_test, y_test):
    """Generates ROC curves for multi-class classification."""
    print("\n--- Generating ROC Curves ---")
    
    # Binarize the output
    y_test_bin = label_binarize(y_test, classes=list(range(len(ATTACK_MAPPING))))
    y_score = model.predict_proba(X_test)
    
    fig, ax = plt.subplots(figsize=(12, 9))
    
    # Compute ROC curve and AUC for each class
    colors = ['#2ecc71', '#f39c12', '#e74c3c', '#8e44ad']
    for i, (label, color) in enumerate(zip(ATTACK_MAPPING.keys(), colors)):
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_score[:, i])
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=color, lw=2.5, 
               label=f'{label} (AUC = {roc_auc:.3f})')
    
    ax.plot([0, 1], [0, 1], 'k--', lw=2, label='Random Classifier')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Positive Rate', fontsize=12, fontweight='bold')
    ax.set_title('ROC Curves for Multi-Class Attack Detection', 
                fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='lower right', fontsize=11)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "roc_curves_multiclass.png"), bbox_inches='tight')
    plt.close()
    print(f"\u2713 ROC curves saved")


def plot_protocol_performance(model, X_test, y_test, test_protocols):
    """Analyzes model performance per protocol."""
    print("\n--- Analyzing Protocol-Specific Performance ---")
    
    y_pred = model.predict(X_test)
    
    protocols = test_protocols.unique()
    protocol_metrics = {}
    
    for protocol in protocols:
        mask = test_protocols == protocol
        if mask.sum() > 0:
            y_true_proto = y_test[mask]
            y_pred_proto = y_pred[mask]
            
            accuracy = accuracy_score(y_true_proto, y_pred_proto)
            
            # Per-class accuracy for this protocol
            class_acc = {}
            for label_name, label_num in ATTACK_MAPPING.items():
                label_mask = y_true_proto == label_num
                if label_mask.sum() > 0:
                    class_acc[label_name] = (y_pred_proto[label_mask] == label_num).sum() / label_mask.sum()
                else:
                    class_acc[label_name] = 0
            
            protocol_metrics[protocol] = {
                'overall_accuracy': accuracy,
                'class_accuracy': class_acc,
                'n_samples': mask.sum()
            }
    
    # Plot protocol performance comparison
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    
    # Overall accuracy by protocol
    proto_names = list(protocol_metrics.keys())
    accuracies = [protocol_metrics[p]['overall_accuracy'] for p in proto_names]
    sample_counts = [protocol_metrics[p]['n_samples'] for p in proto_names]
    
    bars = axes[0].bar(proto_names, accuracies, color=sns.color_palette("Set2", len(proto_names)),
                       edgecolor='black', linewidth=1.5)
    axes[0].set_ylabel('Accuracy', fontsize=12, fontweight='bold')
    axes[0].set_title('Overall Accuracy by Protocol', fontsize=14, fontweight='bold')
    axes[0].set_ylim([0, 1.05])
    axes[0].grid(axis='y', alpha=0.3)
    
    for bar, acc, count in zip(bars, accuracies, sample_counts):
        height = bar.get_height()
        axes[0].text(bar.get_x() + bar.get_width()/2., height + 0.02,
                    f'{acc:.3f}\n(n={count})',
                    ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    # Per-class accuracy by protocol
    class_data = []
    for protocol in proto_names:
        for label_name in ATTACK_MAPPING.keys():
            class_data.append({
                'Protocol': protocol,
                'Attack Type': label_name,
                'Accuracy': protocol_metrics[protocol]['class_accuracy'][label_name]
            })
    
    class_df = pd.DataFrame(class_data)
    class_pivot = class_df.pivot(index='Attack Type', columns='Protocol', values='Accuracy')
    
    class_pivot.plot(kind='bar', ax=axes[1], 
                     color=sns.color_palette("Set2", len(proto_names)),
                     edgecolor='black', linewidth=1.5)
    axes[1].set_ylabel('Accuracy', fontsize=12, fontweight='bold')
    axes[1].set_title('Per-Class Accuracy by Protocol', fontsize=14, fontweight='bold')
    axes[1].set_xlabel('Attack Type', fontsize=12, fontweight='bold')
    axes[1].set_ylim([0, 1.05])
    axes[1].legend(title='Protocol', fontsize=10)
    axes[1].grid(axis='y', alpha=0.3)
    plt.setp(axes[1].xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "protocol_performance_comparison.png"), bbox_inches='tight')
    plt.close()
    print(f"\u2713 Protocol performance comparison saved")
    
    return protocol_metrics


def train_model(X_train, y_train):
    """Trains the Random Forest model with class weights."""
    print("\n--- Training Random Forest Classifier ---")
    
    class_weights = compute_class_weight('balanced', 
                                         classes=np.unique(y_train), 
                                         y=y_train)
    class_weight_dict = dict(zip(np.unique(y_train), class_weights))
    
    print(f"Class weights computed: {class_weight_dict}")
    
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
    
    return model


def evaluate_model(model, X_test, y_test, scaler, test_protocols=None):
    """Evaluates the model on the test set with comprehensive metrics."""
    print("\n--- Model Evaluation ---")
    
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    
    # Detailed classification report
    report_text = classification_report(y_test, y_pred, 
                                       target_names=ATTACK_MAPPING.keys(),
                                       zero_division=0)
    print("\n" + report_text)
    
    with open(os.path.join(RESULTS_DIR, "classification_report.txt"), "w") as f:
        f.write(report_text)
    
    # Enhanced confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    fig, axes = plt.subplots(1, 2, figsize=(18, 7))
    
    # Raw counts
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=ATTACK_MAPPING.keys(), 
                yticklabels=ATTACK_MAPPING.keys(),
                cbar_kws={'label': 'Count'}, ax=axes[0],
                linewidths=1, linecolor='black')
    axes[0].set_title('Confusion Matrix: Packet-Level Classification (Counts)', 
                     fontsize=14, fontweight='bold', pad=15)
    axes[0].set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('True Label', fontsize=12, fontweight='bold')
    
    # Normalized (percentages)
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    sns.heatmap(cm_norm, annot=True, fmt='.2%', cmap='Greens', 
                xticklabels=ATTACK_MAPPING.keys(), 
                yticklabels=ATTACK_MAPPING.keys(),
                cbar_kws={'label': 'Percentage'}, ax=axes[1],
                linewidths=1, linecolor='black')
    axes[1].set_title('Confusion Matrix: Packet-Level Classification (Normalized)', 
                     fontsize=14, fontweight='bold', pad=15)
    axes[1].set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    axes[1].set_ylabel('True Label', fontsize=12, fontweight='bold')
    
    plt.tight_layout()
    cm_path = os.path.join(PLOTS_DIR, "confusion_matrix_enhanced.png")
    plt.savefig(cm_path, bbox_inches='tight')
    plt.close()
    print(f"\u2713 Enhanced confusion matrix saved to {cm_path}")
    
    # Per-class metrics visualization
    fig, ax = plt.subplots(figsize=(12, 7))
    
    class_accuracies = []
    for i, label in enumerate(ATTACK_MAPPING.keys()):
        mask = y_test == i
        if mask.sum() > 0:
            class_acc = (y_pred[mask] == i).sum() / mask.sum()
            class_accuracies.append(class_acc)
            print(f"  {label}: {class_acc:.4f} ({mask.sum()} samples)")
        else:
            class_accuracies.append(0)
    
    x = np.arange(len(ATTACK_MAPPING))
    colors = [ATTACK_COLORS[label] for label in ATTACK_MAPPING.keys()]
    bars = ax.bar(x, class_accuracies, color=colors, edgecolor='black', linewidth=1.5)
    
    ax.set_xlabel('Attack Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Accuracy', fontsize=12, fontweight='bold')
    ax.set_title('Per-Class Classification Accuracy', fontsize=14, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(ATTACK_MAPPING.keys())
    ax.set_ylim([0, 1.05])
    ax.grid(axis='y', alpha=0.3)
    
    for bar, acc in zip(bars, class_accuracies):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                f'{acc:.3f}', ha='center', va='bottom', fontweight='bold', fontsize=11)
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "per_class_accuracy.png"), bbox_inches='tight')
    plt.close()
    print(f"\u2713 Per-class accuracy plot saved")
    
    # ROC curves
    plot_roc_curves(model, X_test_scaled, y_test)
    
    # Protocol-specific performance
    if test_protocols is not None:
        plot_protocol_performance(model, X_test_scaled, y_test, test_protocols)


def analyze_unseen_pcap(pcap_path, model, scaler, feature_names):
    """Performs comprehensive inference on a new pcap file."""
    pcap_name = os.path.basename(pcap_path)
    print(f"\n{'='*60}")
    print(f"IDS INFERENCE: {pcap_name}")
    print(f"{'='*60}")
    
    # Extract features
    new_features_df = extract_packet_features(pcap_path)
    print(f"Extracted {len(new_features_df)} packets from {pcap_name}")
    
    # Prepare X for prediction
    X_new = new_features_df.drop(columns=['packet_number', 'timestamp'])
    X_new = X_new[feature_names]
    
    # Scale and predict with probabilities
    X_new_scaled = scaler.transform(X_new)
    predictions = model.predict(X_new_scaled)
    probabilities = model.predict_proba(X_new_scaled)
    
    predicted_labels = pd.Series(predictions).map(REVERSE_MAPPING)
    
    results_df = pd.DataFrame({
        'packet_number': new_features_df['packet_number'],
        'timestamp': new_features_df['timestamp'],
        'prediction': predicted_labels,
        'confidence': probabilities.max(axis=1)
    })
    
    # Add probability for each class
    for i, label in enumerate(ATTACK_MAPPING.keys()):
        results_df[f'prob_{label}'] = probabilities[:, i]
    
    # Save detailed results
    results_csv = os.path.join(RESULTS_DIR, f"{pcap_name}_detailed_predictions.csv")
    results_df.to_csv(results_csv, index=False)
    print(f"\u2713 Detailed predictions saved to {results_csv}")
    
    # Analysis
    is_normal_only = (predicted_labels == 'N').all()
    attack_occurred = 0 if is_normal_only else 1
    
    unique_attacks = sorted(predicted_labels.unique().tolist(), 
                           key=lambda x: ATTACK_MAPPING.get(x, 99))
    
    packet_counts = predicted_labels.value_counts().to_dict()
    
    # === VISUALIZATION 1: Temporal Analysis ===
    fig = plt.figure(figsize=(18, 10))
    gs = fig.add_gridspec(3, 2, hspace=0.3, wspace=0.3)
    
    ax1 = fig.add_subplot(gs[0, :])
    plot_y = results_df['prediction'].apply(lambda x: ATTACK_MAPPING[x])
    
    colors_map = [ATTACK_COLORS[pred] for pred in results_df['prediction']]
    scatter = ax1.scatter(results_df['timestamp'], plot_y, c=colors_map, 
                         s=40, alpha=0.7, edgecolors='black', linewidth=0.5)
    
    # Create custom legend
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=ATTACK_COLORS[label], edgecolor='black', label=label) 
                      for label in ATTACK_MAPPING.keys()]
    ax1.legend(handles=legend_elements, title="Attack Type", 
              loc="upper right", framealpha=0.95, fontsize=10)
    
    ax1.set_yticks(list(ATTACK_MAPPING.values()))
    ax1.set_yticklabels(list(ATTACK_MAPPING.keys()))
    ax1.set_xlabel("Time (seconds)", fontsize=12, fontweight='bold')
    ax1.set_ylabel("Attack Category", fontsize=12, fontweight='bold')
    ax1.set_title(f"Temporal Attack Detection Analysis: {pcap_name}", 
                 fontsize=14, fontweight='bold', pad=15)
    ax1.grid(axis='y', linestyle='--', alpha=0.4)
    
    # === VISUALIZATION 2: Confidence Distribution ===
    ax2 = fig.add_subplot(gs[1, 0])
    
    for label in unique_attacks:
        mask = results_df['prediction'] == label
        if mask.sum() > 0:
            ax2.hist(results_df.loc[mask, 'confidence'], bins=30, alpha=0.6, 
                    label=label, color=ATTACK_COLORS[label], edgecolor='black')
    
    ax2.set_xlabel('Prediction Confidence', fontsize=11, fontweight='bold')
    ax2.set_ylabel('Number of Packets', fontsize=11, fontweight='bold')
    ax2.set_title('Confidence Score Distribution by Attack Type', fontsize=12, fontweight='bold')
    ax2.legend(fontsize=9)
    ax2.grid(alpha=0.3)
    
    # === VISUALIZATION 3: Attack Distribution Pie ===
    ax3 = fig.add_subplot(gs[1, 1])
    
    sorted_labels = sorted(packet_counts.keys(), key=lambda x: ATTACK_MAPPING.get(x, 99))
    sorted_counts = [packet_counts[label] for label in sorted_labels]
    sorted_colors = [ATTACK_COLORS[label] for label in sorted_labels]
    
    wedges, texts, autotexts = ax3.pie(sorted_counts, labels=sorted_labels, autopct='%1.1f%%',
                                        colors=sorted_colors, startangle=90,
                                        textprops={'fontsize': 10, 'fontweight': 'bold'},
                                        wedgeprops={'edgecolor': 'black', 'linewidth': 1.5})
    ax3.set_title('Attack Type Distribution', fontsize=12, fontweight='bold')
    
    # === VISUALIZATION 4: Attack Transitions ===
    ax4 = fig.add_subplot(gs[2, 0])
    
    transitions = []
    for i in range(1, len(results_df)):
        prev_label = results_df.iloc[i-1]['prediction']
        curr_label = results_df.iloc[i]['prediction']
        if prev_label != curr_label:
            transitions.append({
                'time': results_df.iloc[i]['timestamp'],
                'from': prev_label,
                'to': curr_label,
                'packet': results_df.iloc[i]['packet_number']
            })
    
    if transitions:
        trans_df = pd.DataFrame(transitions)
        trans_text = "Attack State Transitions:\n\n"
        for idx, trans in enumerate(transitions[:10]):  # Show first 10
            trans_text += f"{idx+1}. Pkt {trans['packet']} @ {trans['time']:.3f}s: {trans['from']} \u2192 {trans['to']}\n"
        if len(transitions) > 10:
            trans_text += f"\n... and {len(transitions)-10} more transitions"
        
        ax4.text(0.05, 0.95, trans_text, transform=ax4.transAxes, 
                fontsize=9, verticalalignment='top', family='monospace',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        ax4.axis('off')
        ax4.set_title(f'Detected {len(transitions)} Attack State Transitions', 
                     fontsize=12, fontweight='bold')
    else:
        ax4.text(0.5, 0.5, 'No attack state transitions detected', 
                transform=ax4.transAxes, ha='center', va='center',
                fontsize=11, style='italic')
        ax4.axis('off')
    
    # === VISUALIZATION 5: Sliding Window Statistics ===
    ax5 = fig.add_subplot(gs[2, 1])
    
    window_size = max(100, len(results_df) // 20)
    windows = []
    for i in range(0, len(results_df) - window_size, window_size // 2):
        window = results_df.iloc[i:i+window_size]
        attack_ratio = (window['prediction'] != 'N').sum() / len(window)
        windows.append({
            'center_time': window['timestamp'].mean(),
            'attack_ratio': attack_ratio,
            'avg_confidence': window['confidence'].mean()
        })
    
    if windows:
        win_df = pd.DataFrame(windows)
        ax5_twin = ax5.twinx()
        
        line1 = ax5.plot(win_df['center_time'], win_df['attack_ratio'], 
                        'o-', color='#e74c3c', linewidth=2, markersize=6, 
                        label='Attack Ratio')
        line2 = ax5_twin.plot(win_df['center_time'], win_df['avg_confidence'], 
                             's-', color='#3498db', linewidth=2, markersize=6, 
                             label='Avg Confidence')
        
        ax5.set_xlabel('Time (seconds)', fontsize=11, fontweight='bold')
        ax5.set_ylabel('Attack Ratio', fontsize=11, fontweight='bold', color='#e74c3c')
        ax5_twin.set_ylabel('Average Confidence', fontsize=11, fontweight='bold', color='#3498db')
        ax5.set_title(f'Sliding Window Analysis (window={window_size} packets)', 
                     fontsize=12, fontweight='bold')
        ax5.tick_params(axis='y', labelcolor='#e74c3c')
        ax5_twin.tick_params(axis='y', labelcolor='#3498db')
        ax5.grid(alpha=0.3)
        
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax5.legend(lines, labels, loc='upper left', fontsize=9)
    
    plt.tight_layout()
    plot_path = os.path.join(PLOTS_DIR, f"{pcap_name}_comprehensive_analysis.png")
    plt.savefig(plot_path, bbox_inches='tight')
    plt.close()
    
    # === ADDITIONAL: Protocol breakdown if available ===
    protocol_info = new_features_df[['is_modbus', 'is_tcp', 'is_udp']].sum()
    
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
    print(f"4. Average Prediction Confidence: {results_df['confidence'].mean():.3f}")
    print(f"5. State Transitions Detected: {len(transitions) if transitions else 0}")
    print(f"6. Protocol Distribution:")
    print(f"   - Modbus packets: {int(protocol_info['is_modbus'])}")
    print(f"   - TCP packets: {int(protocol_info['is_tcp'])}")
    print(f"   - UDP packets: {int(protocol_info['is_udp'])}")
    print(f"7. Comprehensive analysis saved to: {plot_path}")
    print("-"*60 + "\n")


def analyze_unseen_directory(feature_names):
    """Analyzes all pcap files in the unseen directory."""
    unseen_dir = os.path.join(PCAP_DIR, UNSEEN_SUBDIR)
    
    if not os.path.exists(unseen_dir):
        print(f"\n\u26a0\ufe0f  Unseen directory '{unseen_dir}' does not exist. Skipping inference.")
        return
    
    unseen_pcaps = glob.glob(os.path.join(unseen_dir, "*.pcap"))
    
    if not unseen_pcaps:
        print(f"\n\u26a0\ufe0f  No pcap files found in '{unseen_dir}'. Skipping inference.")
        return
    
    print(f"\n{'='*60}")
    print(f"ANALYZING UNSEEN DATA")
    print(f"Found {len(unseen_pcaps)} pcap file(s) in {unseen_dir}")
    print(f"{'='*60}")
    
    model_path = os.path.join(RESULTS_DIR, "ids_random_forest_model.joblib")
    scaler_path = os.path.join(RESULTS_DIR, "scaler.joblib")
    
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("\n\u26a0\ufe0f  Model or scaler not found. Please train the model first.")
        return
    
    model = load(model_path)
    scaler = load(scaler_path)
    print(f"Loaded model from {model_path}")
    print(f"Loaded scaler from {scaler_path}")
    
    for pcap_path in sorted(unseen_pcaps):
        try:
            analyze_unseen_pcap(pcap_path, model, scaler, feature_names)
        except Exception as e:
            print(f"\n\u26a0\ufe0f  Error analyzing {os.path.basename(pcap_path)}: {e}")
            import traceback
            traceback.print_exc()


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    create_directories()

    all_data = load_all_training_data()

    if all_data.empty or 'numeric_label' not in all_data.columns:
        print("\n\u274c FATAL ERROR: No data loaded or missing 'numeric_label'.")
    else:
        # Clean data
        all_data = all_data.dropna(subset=['numeric_label'])
        print(f"\n\u2713 Training with {len(all_data)} labeled packets")
        
        # Show label distribution
        print("\nLabel Distribution:")
        for label in sorted(ATTACK_MAPPING.keys(), key=lambda x: ATTACK_MAPPING[x]):
            count = (all_data['label'] == label).sum()
            percentage = (count / len(all_data)) * 100
            print(f"  {label}: {count} packets ({percentage:.1f}%)")
        
        # Visualize class distribution
        plot_class_distribution(all_data)
        
        # Prepare features
        EXCLUDED_COLS = ['pcap_file', 'protocol', 'packet_number', 'timestamp', 'label', 'numeric_label']
        X = all_data.drop(columns=EXCLUDED_COLS)
        y = all_data['numeric_label']
        protocols = all_data['protocol']
        
        feature_names = X.columns.tolist()
        print(f"\nFeatures ({len(feature_names)}): {feature_names}")
        
        # Split data maintaining protocol information
        X_train, X_test, y_train, y_test, proto_train, proto_test = train_test_split(
            X, y, protocols, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"\nTrain set: {len(X_train)} packets")
        print(f"Test set: {len(X_test)} packets")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        X_train_df = pd.DataFrame(X_train_scaled, columns=feature_names)
        
        scaler_path = os.path.join(RESULTS_DIR, "scaler.joblib")
        dump(scaler, scaler_path)
        
        # Save feature names
        feature_names_path = os.path.join(RESULTS_DIR, "feature_names.json")
        with open(feature_names_path, 'w') as f:
            json.dump(feature_names, f)
        
        # Train model
        model = train_model(X_train_df, y_train)
        
        # Generate comprehensive visualizations
        print("\n" + "="*60)
        print("GENERATING COMPREHENSIVE VISUALIZATIONS")
        print("="*60)
        
        plot_feature_importance(model, feature_names, all_data)
        plot_learning_curves(model, X_train_df, y_train)
        
        # Evaluate with all enhancements
        evaluate_model(model, X_test, y_test, scaler, proto_test)
        
        print("\n\u2713 Training and evaluation complete!")
        print(f"\u2713 All plots saved to: {PLOTS_DIR}")

        # Analyze unseen data
        analyze_unseen_directory(feature_names)