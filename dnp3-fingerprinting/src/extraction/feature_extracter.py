import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from .dnp3_parser import DNP3Parser, DNP3Packet, decode_function_code
from .entropy_calculator import EntropyCalculator, calculate_entropy_statistics


class DNP3FeatureExtractor:
    def __init__(self, parser: DNP3Parser):
        self.parser = parser
        self.packets = parser.packets
        self.features_df: Optional[pd.DataFrame] = None
        self.entropy_calc = EntropyCalculator()
    
    def extract_basic_features(self) -> pd.DataFrame:
        features = []
        
        for pkt in self.packets:
            feature_dict = {
                'timestamp': pkt.timestamp,
                'src_ip': pkt.src_ip,
                'dst_ip': pkt.dst_ip,
                'src_port': pkt.src_port,
                'dst_port': pkt.dst_port,
                'transaction_id': pkt.transaction_id,
                'protocol_id': pkt.protocol_id,
                'unit_id': pkt.unit_id,
                'function_code': pkt.function_code,
                'function_name': decode_function_code(pkt.function_code) if pkt.function_code is not None else 'Unknown',
                'packet_length': len(pkt.raw_data),
                'modbus_length': getattr(pkt, 'length', None),
                'data_length': len(pkt.data) if pkt.data else 0,
                'is_valid': pkt.is_valid()
            }
            features.append(feature_dict)
        
        self.features_df = pd.DataFrame(features)
        return self.features_df
    
    def extract_entropy_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        payload_entropies = []
        header_entropies = []
        full_packet_entropies = []
        entropy_classifications = []
        is_normal_entropy = []
        
        for pkt in self.packets:
            payload_entropy = self.entropy_calc.calculate_payload_entropy(pkt.data)
            payload_entropies.append(payload_entropy)
            
            header_entropy = self.entropy_calc.calculate_header_entropy(pkt.raw_data)
            header_entropies.append(header_entropy)
            
            full_entropy = self.entropy_calc.calculate_full_packet_entropy(pkt.raw_data)
            full_packet_entropies.append(full_entropy)
            
            classification = self.entropy_calc.classify_entropy(payload_entropy)
            entropy_classifications.append(classification)
            
            is_normal = self.entropy_calc.is_entropy_normal(payload_entropy)
            is_normal_entropy.append(is_normal)
        
        df['payload_entropy'] = payload_entropies
        df['header_entropy'] = header_entropies
        df['full_packet_entropy'] = full_packet_entropies
        df['entropy_classification'] = entropy_classifications
        df['is_normal_entropy'] = is_normal_entropy
        
        df['payload_entropy_mean_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).mean()
        df['payload_entropy_std_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).std()
        df['payload_entropy_max_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).max()
        df['payload_entropy_min_10'] = df['payload_entropy'].rolling(window=10, min_periods=1).min()
        
        return df
    
    def extract_timing_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        df['time_delta'] = df['timestamp'].diff()
        df['time_delta_ms'] = df['time_delta'] * 1000
        
        df['time_delta_mean_10'] = df['time_delta'].rolling(window=10, min_periods=1).mean()
        df['time_delta_std_10'] = df['time_delta'].rolling(window=10, min_periods=1).std()
        df['time_delta_min_10'] = df['time_delta'].rolling(window=10, min_periods=1).min()
        df['time_delta_max_10'] = df['time_delta'].rolling(window=10, min_periods=1).max()
        
        df['time_delta_cv_10'] = df['time_delta_std_10'] / (df['time_delta_mean_10'] + 1e-9)
        df['time_delta_cv_10'] = df['time_delta_cv_10'].fillna(0)
        
        df['burst_indicator'] = (df['time_delta_ms'] < 5).astype(int)
        df['periodicity_score'] = 1 - df['time_delta_cv_10'].fillna(1)
        
        return df
    
    def extract_packet_size_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        df['packet_length_mean_10'] = df['packet_length'].rolling(window=10, min_periods=1).mean()
        df['packet_length_std_10'] = df['packet_length'].rolling(window=10, min_periods=1).std()
        df['packet_length_max_10'] = df['packet_length'].rolling(window=10, min_periods=1).max()
        df['packet_length_min_10'] = df['packet_length'].rolling(window=10, min_periods=1).min()
        
        df['packet_length_cv_10'] = df['packet_length_std_10'] / (df['packet_length_mean_10'] + 1e-9)
        df['packet_length_cv_10'] = df['packet_length_cv_10'].fillna(0)
        
        return df
    
    def extract_function_code_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        function_code_dummies = pd.get_dummies(df['function_code'], prefix='fc')
        df = pd.concat([df, function_code_dummies], axis=1)
        
        df['is_read_operation'] = df['function_code'].isin([1]).astype(int)
        df['is_write_operation'] = df['function_code'].isin([2, 4, 5]).astype(int)
        df['is_error_response'] = (df['function_code'] >= 128).astype(int)
        
        df['function_code_changes'] = (df['function_code'] != df['function_code'].shift()).astype(int)
        df['function_code_stability_10'] = 1 - df['function_code_changes'].rolling(window=10, min_periods=1).mean()
        
        return df
    
    def extract_protocol_validation_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        df['protocol_id_valid'] = df['protocol_id'].apply(lambda x: 1 if x == 0 else 0)
        df['unit_id_valid'] = df['unit_id'].apply(lambda x: 1 if (x is not None and x >= 0) else 0)
        df['function_code_valid'] = df['function_code'].apply(lambda x: 1 if (x is not None and 0 <= x <= 255) else 0)
        
        if 'modbus_length' in df.columns and 'data_length' in df.columns:
            df['length_consistent'] = ((df['modbus_length'] - df['data_length']).abs() <= 5).astype(int)
        else:
            df['length_consistent'] = 1
        
        return df
    
    def extract_flow_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        src_counts = df.groupby('src_ip').size().to_dict()
        dst_counts = df.groupby('dst_ip').size().to_dict()
        unit_counts = df.groupby('unit_id').size().to_dict()
        
        df['packets_per_src'] = df['src_ip'].map(src_counts)
        df['packets_per_dst'] = df['dst_ip'].map(dst_counts)
        df['packets_per_unit'] = df['unit_id'].map(unit_counts)
        
        df['unique_src_ips'] = df['src_ip'].nunique()
        df['unique_dst_ips'] = df['dst_ip'].nunique()
        df['unique_unit_ids'] = df['unit_id'].nunique()
        
        return df
    
    def extract_derived_features(self) -> pd.DataFrame:
        if self.features_df is None:
            self.extract_basic_features()
        
        df = self.features_df.copy()
        
        if 'payload_entropy_std_10' in df.columns:
            df['entropy_stability'] = 1 / (1 + df['payload_entropy_std_10'].fillna(0))
        
        if 'is_read_operation' in df.columns and 'is_write_operation' in df.columns:
            read_total = df['is_read_operation'].sum()
            write_total = df['is_write_operation'].sum()
            df['read_write_ratio'] = read_total / max(write_total, 1)
        
        if 'time_delta' in df.columns:
            time_range = df['timestamp'].max() - df['timestamp'].min()
            df['traffic_intensity'] = len(df) / max(time_range, 1)
        
        return df
    
    def extract_all_features(self) -> pd.DataFrame:
        self.extract_basic_features()
        df = self.extract_entropy_features()
        self.features_df = df
        df = self.extract_timing_features()
        self.features_df = df
        df = self.extract_packet_size_features()
        self.features_df = df
        df = self.extract_function_code_features()
        self.features_df = df
        df = self.extract_protocol_validation_features()
        self.features_df = df
        df = self.extract_flow_features()
        self.features_df = df
        df = self.extract_derived_features()
        self.features_df = df
        return df
    
    def get_feature_matrix(self, feature_columns: Optional[List[str]] = None) -> np.ndarray:
        if self.features_df is None:
            self.extract_all_features()
        
        if feature_columns is None:
            exclude_cols = {'timestamp', 'src_ip', 'dst_ip', 'function_name', 
                          'entropy_classification', 'src_port', 'dst_port', 
                          'is_normal_entropy'}
            feature_columns = [col for col in self.features_df.columns 
                             if col not in exclude_cols and 
                             pd.api.types.is_numeric_dtype(self.features_df[col])]
        
        return self.features_df[feature_columns].fillna(0).values
    
    def get_summary_statistics(self) -> Dict:
        if self.features_df is None:
            self.extract_basic_features()
        
        if self.features_df.empty:
            return {
                'total_packets': 0,
                'unique_function_codes': 0,
                'function_code_distribution': {},
                'packet_length': {'mean': 0.0, 'std': 0.0, 'min': 0, 'max': 0, 'median': 0.0, 'cv': 0.0},
                'timing': {'mean_ms': 0.0, 'std_ms': 0.0, 'min_ms': 0.0, 'max_ms': 0.0, 'median_ms': 0.0, 'cv': 0.0},
                'network': {'unique_src_ips': 0, 'unique_dst_ips': 0, 'unique_unit_ids': 0, 'unit_id_distribution': {}},
                'entropy': {'payload': calculate_entropy_statistics([]), 'header': calculate_entropy_statistics([]), 'normal_entropy_percentage': 0.0},
                'operations': {'read_count': 0, 'write_count': 0, 'error_count': 0, 'read_percentage': 0.0, 'write_percentage': 0.0, 'error_percentage': 0.0},
                'protocol_compliance': {'valid_packets': 0, 'invalid_packets': 0, 'validity_rate': 0.0}
            }
        
        if 'payload_entropy' not in self.features_df.columns:
            self.extract_entropy_features()
        
        if 'time_delta' not in self.features_df.columns:
            self.extract_timing_features()
        
        stats = {
            'total_packets': len(self.packets),
            'unique_function_codes': self.features_df['function_code'].nunique(),
            'function_code_distribution': self.features_df['function_code'].value_counts().to_dict(),
            
            'packet_length': {
                'mean': float(self.features_df['packet_length'].mean()),
                'std': float(self.features_df['packet_length'].std()),
                'min': int(self.features_df['packet_length'].min()),
                'max': int(self.features_df['packet_length'].max()),
                'median': float(self.features_df['packet_length'].median()),
                'cv': float(self.features_df['packet_length'].std() / self.features_df['packet_length'].mean())
            },
            
            'timing': {
                'mean_ms': float(self.features_df['time_delta'].mean() * 1000) if len(self.features_df) > 1 else 0,
                'std_ms': float(self.features_df['time_delta'].std() * 1000) if len(self.features_df) > 1 else 0,
                'min_ms': float(self.features_df['time_delta'].min() * 1000) if len(self.features_df) > 1 else 0,
                'max_ms': float(self.features_df['time_delta'].max() * 1000) if len(self.features_df) > 1 else 0,
                'median_ms': float(self.features_df['time_delta'].median() * 1000) if len(self.features_df) > 1 else 0,
                'cv': float(self.features_df['time_delta'].std() / self.features_df['time_delta'].mean()) if len(self.features_df) > 1 and self.features_df['time_delta'].mean() > 0 else 0
            },
            
            'network': {
                'unique_src_ips': self.features_df['src_ip'].nunique(),
                'unique_dst_ips': self.features_df['dst_ip'].nunique(),
                'unique_unit_ids': self.features_df['unit_id'].nunique(),
                'unit_id_distribution': self.features_df['unit_id'].value_counts().to_dict(),
            },
        }
        
        if 'payload_entropy' in self.features_df.columns:
            payload_entropies = self.features_df['payload_entropy'].dropna().tolist()
            header_entropies = self.features_df['header_entropy'].dropna().tolist()
            
            stats['entropy'] = {
                'payload': calculate_entropy_statistics(payload_entropies),
                'header': calculate_entropy_statistics(header_entropies),
                'normal_entropy_percentage': float(self.features_df['is_normal_entropy'].mean() * 100)
            }
        
        if 'is_read_operation' in self.features_df.columns:
            stats['operations'] = {
                'read_count': int(self.features_df['is_read_operation'].sum()),
                'write_count': int(self.features_df['is_write_operation'].sum()),
                'error_count': int(self.features_df['is_error_response'].sum()),
                'read_percentage': float(self.features_df['is_read_operation'].mean() * 100),
                'write_percentage': float(self.features_df['is_write_operation'].mean() * 100),
                'error_percentage': float(self.features_df['is_error_response'].mean() * 100)
            }
        
        if 'is_valid' in self.features_df.columns:
            stats['protocol_compliance'] = {
                'valid_packets': int(self.features_df['is_valid'].sum()),
                'invalid_packets': int((~self.features_df['is_valid']).sum()),
                'validity_rate': float(self.features_df['is_valid'].mean() * 100)
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
    print(f"\n{'='*60}")
    print(f"Processing DNP3 PCAP: {pcap_file}")
    print(f"{'='*60}")
    
    parser = DNP3Parser(pcap_file)
    parser.parse()
    
    if parser.get_packet_count() == 0:
        print("WARNING: No valid DNP3 packets found!")
        return pd.DataFrame()
    
    extractor = DNP3FeatureExtractor(parser)
    features_df = extractor.extract_all_features()
    
    print("\n=== FEATURE EXTRACTION SUMMARY ===")
    stats = extractor.get_summary_statistics()
    
    print(f"\nPacket Statistics:")
    print(f"  Total packets: {stats['total_packets']}")
    print(f"  Unique function codes: {stats['unique_function_codes']}")
    
    print(f"\nPacket Length:")
    print(f"  Mean: {stats['packet_length']['mean']:.2f} bytes")
    print(f"  Std: {stats['packet_length']['std']:.2f} bytes")
    print(f"  Range: {stats['packet_length']['min']}-{stats['packet_length']['max']} bytes")
    
    print(f"\nTiming:")
    print(f"  Mean inter-arrival: {stats['timing']['mean_ms']:.2f} ms")
    
    if 'entropy' in stats:
        print(f"\nEntropy Analysis:")
        print(f"  Payload entropy mean: {stats['entropy']['payload']['mean']:.4f} bits")
        print(f"  Normal entropy packets: {stats['entropy']['normal_entropy_percentage']:.1f}%")
    
    print(f"\nFunction Code Distribution:")
    for fc, count in sorted(stats['function_code_distribution'].items()):
        fc_name = decode_function_code(fc)
        percentage = (count / stats['total_packets']) * 100
        print(f"  FC {fc} ({fc_name}): {count} ({percentage:.1f}%)")
    
    if output_file:
        extractor.save_features(output_file)
    
    print(f"\n{'='*60}\n")
    
    return features_df