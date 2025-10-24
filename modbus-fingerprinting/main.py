# main.py
from .src.extraction.feature_extracter import extract_features_from_pcap
import os

# 1. Define the path to your Modbus PCAP file
PCAP_FILE = 'modbus-fingerprinting/data/raw/MODBUS/Modbus/Modbus.pcap'

# 2. Define an optional output file for the extracted features
OUTPUT_CSV = 'modbus-fingerprinting/csv_outputs/modbus_features.csv'

if __name__ == '__main__':
    if not os.path.exists(PCAP_FILE):
        print(f"Error: PCAP file not found at {PCAP_FILE}")
    else:
        # Run the extraction and analysis
        features_df = extract_features_from_pcap(PCAP_FILE, OUTPUT_CSV)
        
        # You can inspect the first few rows of the generated DataFrame
        if not features_df.empty:
            print("\nHead of Extracted Features DataFrame:")
            print(features_df.head())