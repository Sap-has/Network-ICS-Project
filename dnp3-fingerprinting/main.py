from src.extraction.feature_extractor import extract_features_from_pcap
import os

PCAP_FILE = 'data/raw/DNP3/dnp3.pcap'
OUTPUT_CSV = 'dnp3_features.csv'

if __name__ == '__main__':
    if not os.path.exists(PCAP_FILE):
        print(f"Error: PCAP file not found at {PCAP_FILE}")
        
        pcap_dir = 'data/raw/DNP3'
        if os.path.exists(pcap_dir):
            print(f"\nSearching for PCAP files in {pcap_dir}...")
            for root, dirs, files in os.walk(pcap_dir):
                for file in files:
                    if file.endswith('.pcap') or file.endswith('.pcapng'):
                        pcap_path = os.path.join(root, file)
                        print(f"\nFound: {pcap_path}")
                        features_df = extract_features_from_pcap(pcap_path, f"output_{file}.csv")
                        
                        if not features_df.empty:
                            print("\nFirst few rows:")
                            print(features_df.head())
    else:
        features_df = extract_features_from_pcap(PCAP_FILE, OUTPUT_CSV)
        
        if not features_df.empty:
            print("\nFirst few rows:")
            print(features_df.head())