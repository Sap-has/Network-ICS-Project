import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from .modbus_parser import ModbusParser, ModbusPacket, decode_function_code
from .entropy_calculator import EntropyCalculator, calculate_entropy_statistics

class ModbusFeatureExtractor:    
    def __init__(self, parser: ModbusParser):
        self.parser = parser
        self.packets = parser.packets
        self.features_df: Optional[pd.DataFrame] = None
        self.entropy_calc = EntropyCalculator()
    
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
    
    def extract_entropy_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        # Calculate entropy for each packet
        payload_entropies = []
        header_entropies = []
        full_packet_entropies = []
        entropy_classifications = []
        is_normal_entropy = []
        
        for pkt in self.packets:
            # Payload entropy (data field only)
            payload_entropy = self.entropy_calc.calculate_payload_entropy(pkt.data)
            payload_entropies.append(payload_entropy)
            
            # Header entropy (MBAP header)
            header_entropy = self.entropy_calc.calculate_header_entropy(pkt.raw_data)
            header_entropies.append(header_entropy)
            
            # Full packet entropy
            full_entropy = self.entropy_calc.calculate_full_packet_entropy(pkt.raw_data)
            full_packet_entropies.append(full_entropy)
            
            # Classification
            classification = self.entropy_calc.classify_entropy(payload_entropy)
            entropy_classifications.append(classification)
            
            # Check if within normal range (3.5-6.5 bits for payload)
            is_normal = self.entropy_calc.is_entropy_normal(payload_entropy)
            is_normal_entropy.append(is_normal)
        
        # Add entropy features to dataframe
        df['payload_entropy'] = payload_entropies
        df['header_entropy'] = header_entropies
        df['full_packet_entropy'] = full_packet_entropies
        df['entropy_classification'] = entropy_classifications
        df['is_normal_entropy'] = is_normal_entropy
        
        # Rolling entropy statistics (window of 10 packets)
        df['payload_entropy_mean_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).mean()
        df['payload_entropy_std_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).std()
        df['payload_entropy_max_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).max()
        df['payload_entropy_min_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).min()
        
        return df
    
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
        
        # Rolling statistics for inter-arrival time
        df['time_delta_mean_10'] = df['time_delta'].rolling(window=10, min_periods=1).mean()
        df['time_delta_std_10'] = df['time_delta'].rolling(window=10, min_periods=1).std()
        
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
        entropy_df = self.extract_entropy_features()
        cat_df = self.extract_categorical_features()
        
        return cat_df
    
    def get_feature_matrix(self, feature_columns: Optional[List[str]] = None) -> np.ndarray:
        if self.features_df is None:
            self.extract_all_features()
        
        if feature_columns is None:
            # Select only numeric columns, excluding identifiers
            exclude_cols = ['timestamp', 'src_ip', 'dst_ip', 'function_name', 
                          'entropy_classification']
            feature_columns = [col for col in self.features_df.columns 
                             if col not in exclude_cols and 
                             pd.api.types.is_numeric_dtype(self.features_df[col])]
        
        return self.features_df[feature_columns].fillna(0).values
    
    def get_summary_statistics(self) -> Dict:
        if self.features_df is None:
            self.extract_basic_features()
        
        # Extract entropy features if not already done
        if 'payload_entropy' not in self.features_df.columns:
            self.extract_entropy_features()
        
        stats = {
            'total_packets': len(self.packets),
            'unique_function_codes': self.features_df['function_code'].nunique(),
            'function_code_distribution': self.features_df['function_code'].value_counts().to_dict(),
            
            # Packet length statistics
            'packet_length_mean': float(self.features_df['packet_length'].mean()),
            'packet_length_std': float(self.features_df['packet_length'].std()),
            'packet_length_min': int(self.features_df['packet_length'].min()),
            'packet_length_max': int(self.features_df['packet_length'].max()),
            'packet_length_median': float(self.features_df['packet_length'].median()),
            
            # Timing statistics
            'time_delta_mean_ms': float(self.features_df['time_delta'].mean() * 1000) if len(self.features_df) > 1 else 0,
            'time_delta_std_ms': float(self.features_df['time_delta'].std() * 1000) if len(self.features_df) > 1 else 0,
            'time_delta_min_ms': float(self.features_df['time_delta'].min() * 1000) if len(self.features_df) > 1 else 0,
            'time_delta_max_ms': float(self.features_df['time_delta'].max() * 1000) if len(self.features_df) > 1 else 0,
            
            # Network statistics
            'unique_src_ips': self.features_df['src_ip'].nunique(),
            'unique_dst_ips': self.features_df['dst_ip'].nunique(),
            'unique_unit_ids': self.features_df['unit_id'].nunique(),
            'unit_id_distribution': self.features_df['unit_id'].value_counts().to_dict(),
        }
        
        if 'payload_entropy' in self.features_df.columns:
            payload_entropies = self.features_df['payload_entropy'].dropna().tolist()
            header_entropies = self.features_df['header_entropy'].dropna().tolist()
            
            stats['entropy'] = {
                'payload': calculate_entropy_statistics(payload_entropies),
                'header': calculate_entropy_statistics(header_entropies),
                'normal_entropy_percentage': float(self.features_df['is_normal_entropy'].mean() * 100)
            }
        
        return stats
    
    def get_feature_importance_summary(self) -> Dict:
        if self.features_df is None:
            self.extract_all_features()
        
        summary = {
            'packet_characteristics': {
                'mean_size': float(self.features_df['packet_length'].mean()),
                'size_variability': float(self.features_df['packet_length'].std()),
            },
            'timing_characteristics': {
                'mean_inter_arrival_ms': float(self.features_df['time_delta'].mean() * 1000) if len(self.features_df) > 1 else 0,
                'timing_regularity': float(self.features_df['time_delta'].std() * 1000) if len(self.features_df) > 1 else 0,
            },
            'protocol_usage': {
                'function_codes': self.features_df['function_code'].value_counts().to_dict(),
                'read_write_ratio': float(self.features_df['is_read_operation'].sum() / 
                                        max(self.features_df['is_write_operation'].sum(), 1)),
            },
            'entropy_profile': {
                'mean_payload_entropy': float(self.features_df['payload_entropy'].mean()),
                'mean_header_entropy': float(self.features_df['header_entropy'].mean()),
                'entropy_stability': float(self.features_df['payload_entropy'].std()),
            } if 'payload_entropy' in self.features_df.columns else None,
            'network_topology': {
                'unique_sources': self.features_df['src_ip'].nunique(),
                'unique_destinations': self.features_df['dst_ip'].nunique(),
                'unique_units': self.features_df['unit_id'].nunique(),
            }
        }
        
        return summary
    
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
    print(f"\n{'='*60}")
    print(f"Processing: {pcap_file}")
    print(f"{'='*60}")
    
    parser = ModbusParser(pcap_file)
    parser.parse()
    
    if parser.get_packet_count() == 0:
        print("WARNING: No valid Modbus packets found!")
        return pd.DataFrame()
    
    # Extract features
    extractor = ModbusFeatureExtractor(parser)
    features_df = extractor.extract_all_features()
    
    # Print summary
    print("\n=== FEATURE EXTRACTION SUMMARY ===")
    stats = extractor.get_summary_statistics()
    
    print(f"\nPacket Statistics:")
    print(f"  Total packets: {stats['total_packets']}")
    print(f"  Unique function codes: {stats['unique_function_codes']}")
    
    print(f"\nPacket Length:")
    print(f"  Mean: {stats['packet_length_mean']:.2f} bytes")
    print(f"  Std: {stats['packet_length_std']:.2f} bytes")
    print(f"  Range: {stats['packet_length_min']}-{stats['packet_length_max']} bytes")
    
    print(f"\nTiming:")
    print(f"  Mean inter-arrival: {stats['time_delta_mean_ms']:.2f} ms")
    print(f"  Std inter-arrival: {stats['time_delta_std_ms']:.2f} ms")
    
    if 'entropy' in stats:
        print(f"\nEntropy Analysis:")
        print(f"  Payload entropy mean: {stats['entropy']['payload']['mean']:.4f} bits")
        print(f"  Payload entropy std: {stats['entropy']['payload']['std']:.4f} bits")
        print(f"  Payload entropy range: {stats['entropy']['payload']['min']:.4f}-{stats['entropy']['payload']['max']:.4f} bits")
        print(f"  Normal entropy packets: {stats['entropy']['normal_entropy_percentage']:.1f}%")
        print(f"  Header entropy mean: {stats['entropy']['header']['mean']:.4f} bits")
    
    print(f"\nFunction Code Distribution:")
    for fc, count in sorted(stats['function_code_distribution'].items()):
        fc_name = decode_function_code(fc)
        percentage = (count / stats['total_packets']) * 100
        print(f"  FC {fc} ({fc_name}): {count} ({percentage:.1f}%)")
    
    print(f"\nNetwork:")
    print(f"  Unique source IPs: {stats['unique_src_ips']}")
    print(f"  Unique destination IPs: {stats['unique_dst_ips']}")
    print(f"  Unique unit IDs: {stats['unique_unit_ids']}")
    
    # Save if output file specified
    if output_file:
        extractor.save_features(output_file)
    
    print(f"\n{'='*60}\n")
    
    return features_df
