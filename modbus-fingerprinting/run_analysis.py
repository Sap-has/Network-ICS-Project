import os
import pandas as pd
from src.extraction.feature_extracter import extract_features_from_pcap
from src.analysis.visualizer import ModbusAnalysisTool
from src.analysis.anomaly_detector import ModbusAnomalyDetector, group_and_compute_stats

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
        
    # 2. Run anomaly detection
    # The detector will add the 'is_anomaly' column to its internal DF.
    detector = ModbusAnomalyDetector(features_df)
    anomalies = detector.detect_anomalies() 
    
    # Use the detector's internal, flagged DataFrame for analysis
    flagged_df = detector.df
    
    # 3. Create visualizations and analysis report (using the flagged DF)
    analyzer = ModbusAnalysisTool(flagged_df) 
    # Pass the anomalies report to the export method
    analyzer.export_analysis_results(pcap_output_dir, anomalies_report=anomalies)
    
    # 4. Run group stats (kept for project continuity)
    summary_df, freq_dists = group_and_compute_stats(features_df) 
    
    # Save anomaly detection results
    if anomalies:
        import json
        with open(os.path.join(pcap_output_dir, 'anomalies.json'), 'w') as f:
            # Save the list of anomalous packets and their reasons
            json.dump(anomalies, f, indent=2)
    
    print(f"Analysis completed for {pcap_path}")
    return flagged_df

def main():
    # Base directory containing PCAP files
    base_dir = 'data/raw/MODBUS'
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
        # Use the flagged features df from process_pcap_file
        flagged_features_df = process_pcap_file(pcap_file, output_dir)
        if flagged_features_df is not None and not flagged_features_df.empty:
            flagged_features_df['source_pcap'] = os.path.basename(pcap_file)
            all_features.append(flagged_features_df)
    
    # Combine all features for comparative analysis
    if all_features:
        combined_df = pd.concat(all_features, ignore_index=True)
        combined_df.to_csv(os.path.join(output_dir, 'all_features.csv'), index=False)
        
        # Run combined analysis (Note: Anomalies won't be recalculated/plotted here unless
        # you rerun the detector on the combined_df, which is outside the scope of this change)
        analyzer = ModbusAnalysisTool(combined_df)
        analyzer.export_analysis_results(os.path.join(output_dir, 'combined_analysis'))

if __name__ == '__main__':
    main()



## Create Model to detect anomalies
## Run hypotheticla network and run attacker, attacker does attack, and our program then reads behavior, 
# then tracks the time where odd behavior was detected and from who, attacker attacks randomly, point of 
# program is to see if it can detect attack
# then collect traffic
# compare to actuall attacks vs detected attacks
# can it catogarize attacks as well (attacks can be randomized)
# Large environment (multiple attacvkers and attacks), and be abl to detect attacks and attack types
# focus on Modbus/DNP3


## Research into machine learning models for anomaly detection in Modbus/DNP3 traffic
## Create a bigger network enviroment with multiple attackers and attack types)
## Collect traffic data from the network under normal and attack conditions
## The program should be able to detect and categorize attacks based on the collected traffic data
## Shoudl be able to handle randomized attacks and multiple attackers
## Should say who the attacker is, what time the attack happened, and what type of attack it was
## Evaluate the performance of the anomaly detection model in terms of accuracy, precision, recall, and F1-score
## Can scale back to Modbus only, then expand to DNP3

