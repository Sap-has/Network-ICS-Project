import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from .modbus_parser import ModbusParser, ModbusPacket, decode_function_code


class ModbusFeatureExtractor:    
    def __init__(self, parser: ModbusParser):
        self.parser = parser
        self.packets = parser.packets
        self.features_df: Optional[pd.DataFrame] = None
    
    def extract_basic_features(self) -> pd.DataFrame:
        features = []
        
        for pkt in self.packets:
            feature_dict = {
                # Temporal features
                'timestamp': pkt.timestamp,
                
                # Network features
                'src_ip': pkt.src_ip,
                'dst_ip': pkt.dst_ip,
                'src_port': pkt.src_port,
                'dst_port': pkt.dst_port,
                
                # Modbus header features
                'transaction_id': pkt.transaction_id,
                'protocol_id': pkt.protocol_id,
                'unit_id': pkt.unit_id,
                'function_code': pkt.function_code,
                'function_name': decode_function_code(pkt.function_code) if pkt.function_code else 'Unknown',
                
                # Length features
                'packet_length': len(pkt.raw_data),
                'modbus_length': pkt.length,
                'data_length': len(pkt.data) if pkt.data else 0,
                
                # Validity
                'is_valid': pkt.is_valid()
            }
            
            features.append(feature_dict)
        
        self.features_df = pd.DataFrame(features)
        return self.features_df
    
    def extract_statistical_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        # Time-based features
        df['time_delta'] = df['timestamp'].diff()
        
        # Rolling statistics for packet length (window of 10)
        df['packet_length_mean_10'] = df['packet_length'].rolling(window=10, min_periods=1).mean()
        df['packet_length_std_10'] = df['packet_length'].rolling(window=10, min_periods=1).std()
        df['packet_length_max_10'] = df['packet_length'].rolling(window=10, min_periods=1).max()
        df['packet_length_min_10'] = df['packet_length'].rolling(window=10, min_periods=1).min()
        
        # Function code frequency in rolling window
        df['function_code_changes'] = (df['function_code'] != df['function_code'].shift()).astype(int)
        
        return df
    
    def extract_categorical_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        # One-hot encode function codes
        function_code_dummies = pd.get_dummies(df['function_code'], prefix='fc')
        df = pd.concat([df, function_code_dummies], axis=1)
        
        # Binary features
        df['is_read_operation'] = df['function_code'].isin([1, 2, 3, 4]).astype(int)
        df['is_write_operation'] = df['function_code'].isin([5, 6, 15, 16]).astype(int)
        df['is_error_response'] = (df['function_code'] >= 128).astype(int)
        
        return df
    
    def extract_all_features(self) -> pd.DataFrame:
        basic_df = self.extract_basic_features()
        stat_df = self.extract_statistical_features()
        cat_df = self.extract_categorical_features()
        
        return cat_df
    
    def get_feature_matrix(self, feature_columns: Optional[List[str]] = None) -> np.ndarray:
        if self.features_df is None:
            self.extract_all_features()
        
        if feature_columns is None:
            # Select only numeric columns, excluding identifiers
            exclude_cols = ['timestamp', 'src_ip', 'dst_ip', 'function_name']
            feature_columns = [col for col in self.features_df.columns 
                             if col not in exclude_cols and 
                             pd.api.types.is_numeric_dtype(self.features_df[col])]
        
        return self.features_df[feature_columns].fillna(0).values
    
    def get_summary_statistics(self) -> Dict:
        if self.features_df is None:
            self.extract_basic_features()
        
        stats = {
            'total_packets': len(self.packets),
            'unique_function_codes': self.features_df['function_code'].nunique(),
            'function_code_distribution': self.features_df['function_code'].value_counts().to_dict(),
            'avg_packet_length': self.features_df['packet_length'].mean(),
            'std_packet_length': self.features_df['packet_length'].std(),
            'avg_time_delta': self.features_df['timestamp'].diff().mean() if len(self.features_df) > 1 else 0,
            'unique_src_ips': self.features_df['src_ip'].nunique(),
            'unique_dst_ips': self.features_df['dst_ip'].nunique(),
        }
        
        return stats
    
    def save_features(self, output_file: str, format: str = 'csv'):
        if self.features_df is None:
            self.extract_all_features()
        
        if format == 'csv':
            self.features_df.to_csv(output_file, index=False)
        elif format == 'json':
            self.features_df.to_json(output_file, orient='records', lines=True)
        elif format == 'parquet':
            self.features_df.to_parquet(output_file, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        print(f"Features saved to {output_file}")


def extract_features_from_pcap(pcap_file: str, output_file: Optional[str] = None) -> pd.DataFrame:
    # Parse packets
    parser = ModbusParser(pcap_file)
    parser.parse()
    
    # Extract features
    extractor = ModbusFeatureExtractor(parser)
    features_df = extractor.extract_all_features()
    
    # Print summary
    print("\n=== Feature Extraction Summary ===")
    stats = extractor.get_summary_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    # Save if output file specified
    if output_file:
        extractor.save_features(output_file)
    
    return features_df