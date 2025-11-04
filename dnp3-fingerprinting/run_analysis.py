import os
import pandas as pd
from src.extraction.feature_extracter import extract_features_from_pcap
from src.analysis.visualizer import ModbusAnalysisTool
from src.analysis.anomaly_detector import group_and_compute_stats

def process_pcap_file(pcap_path, output_dir):
    """Process a single PCAP file and generate analysis results"""
    print(f"\nProcessing: {pcap_path}")
    
    # Create output directory for this PCAP
    pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]
    pcap_output_dir = os.path.join(output_dir, pcap_name)
    os.makedirs(pcap_output_dir, exist_ok=True)
    
    # 1. Extract features
    features_df = extract_features_from_pcap(pcap_path)
    if features_df is None or features_df.empty:
        print(f"No features extracted from {pcap_path}")
        return
    
    # 2. Create visualizations and analysis report
    analyzer = ModbusAnalysisTool(features_df)
    analyzer.export_analysis_results(pcap_output_dir)
    
    # 3. Run anomaly detection
    summary_df, freq_dists = group_and_compute_stats(features_df)
    
    # Save anomaly detection results
    anomalies = analyzer.detect_potential_anomalies()
    if anomalies:
        import json
        with open(os.path.join(pcap_output_dir, 'anomalies.json'), 'w') as f:
            json.dump(anomalies, f, indent=2)
    
    print(f"Analysis completed for {pcap_path}")
    return features_df

def main():
    # Base directory containing PCAP files
    base_dir = 'data/raw/DNP3'
    output_dir = 'analysis_results'
    
    # Create main output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # List all PCAP files
    pcap_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.pcap'):
                pcap_files.append(os.path.join(root, file))
    
    print(f"Found {len(pcap_files)} PCAP files to process")
    
    # Process each PCAP file
    all_features = []
    for pcap_file in pcap_files:
        features_df = process_pcap_file(pcap_file, output_dir)
        if features_df is not None and not features_df.empty:
            features_df['source_pcap'] = os.path.basename(pcap_file)
            all_features.append(features_df)
    
    # Combine all features for comparative analysis
    if all_features:
        combined_df = pd.concat(all_features, ignore_index=True)
        combined_df.to_csv(os.path.join(output_dir, 'all_features.csv'), index=False)
        
        # Run comparative analysis
        analyzer = ModbusAnalysisTool(combined_df)
        analyzer.export_analysis_results(os.path.join(output_dir, 'combined_analysis'))

if __name__ == '__main__':
    main()