import unittest
import struct
import numpy as np
import pandas as pd
from src.extraction.modbus_parser import ModbusPacket, ModbusParser
from src.extraction.feature_extracter import ModbusFeatureExtractor
from src.extraction.entropy_calculator import EntropyCalculator


class TestFeatureExtraction(unittest.TestCase):
    
    def create_mock_parser_with_packets(self, num_packets=20, vary_timing=True, vary_function_codes=True):
        class MockParser:
            def __init__(self):
                self.packets = []
        
        parser = MockParser()
        base_time = 1234567890.0
        
        for i in range(num_packets):
            transaction_id = struct.pack('>H', i)
            protocol_id = struct.pack('>H', 0)
            length = struct.pack('>H', 6)
            unit_id = struct.pack('B', (i % 5) + 1)
            
            if vary_function_codes:
                fc_options = [1, 3, 4, 16]
                fc = struct.pack('B', fc_options[i % len(fc_options)])
            else:
                fc = struct.pack('B', 3)
            
            data = struct.pack('>HH', 0, 10)
            raw_data = transaction_id + protocol_id + length + unit_id + fc + data
            
            if vary_timing:
                time_offset = i * 0.1 + (i % 3) * 0.02
            else:
                time_offset = i * 0.1
            
            pkt = ModbusPacket(
                timestamp=base_time + time_offset,
                src_ip="192.168.1.100",
                dst_ip=f"192.168.1.{10 + (i % 3)}",
                src_port=50000,
                dst_port=502,
                raw_data=raw_data
            )
            parser.packets.append(pkt)
        
        return parser
    
    def test_basic_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_basic_features()
        
        self.assertEqual(len(df), 20)
        
        required_columns = [
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'transaction_id', 'protocol_id', 'unit_id', 'function_code',
            'packet_length', 'modbus_length', 'data_length', 'is_valid'
        ]
        for col in required_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue(df['is_valid'].all())
        self.assertEqual(df['protocol_id'].unique()[0], 0)
        self.assertTrue((df['unit_id'] >= 1).all() and (df['unit_id'] <= 5).all())
    
    def test_entropy_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_entropy_features()
        
        entropy_columns = [
            'payload_entropy', 'header_entropy', 'full_packet_entropy',
            'payload_entropy_mean_10', 'payload_entropy_std_10',
            'payload_entropy_max_10', 'payload_entropy_min_10'
        ]
        for col in entropy_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue((df['payload_entropy'] >= 0).all())
        self.assertTrue((df['payload_entropy'] <= 8).all())
        self.assertTrue((df['header_entropy'] >= 0).all())
        self.assertTrue((df['header_entropy'] <= 8).all())
        
        self.assertFalse(df['payload_entropy_mean_10'].isna().all())
    
    def test_timing_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20, vary_timing=True)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_timing_features()
        
        timing_columns = [
            'time_delta', 'time_delta_ms',
            'time_delta_mean_10', 'time_delta_std_10',
            'time_delta_min_10', 'time_delta_max_10',
            'time_delta_cv_10', 'burst_indicator', 'periodicity_score'
        ]
        for col in timing_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue((df['time_delta_ms'].dropna() > 0).all())
        self.assertTrue((df['time_delta_cv_10'] >= 0).all())
        self.assertTrue((df['periodicity_score'] >= 0).all())
        self.assertTrue((df['periodicity_score'] <= 1).all())
    
    def test_packet_size_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_packet_size_features()
        
        size_columns = [
            'packet_length_mean_10', 'packet_length_std_10',
            'packet_length_max_10', 'packet_length_min_10',
            'packet_length_cv_10'
        ]
        for col in size_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue((df['packet_length_mean_10'] > 0).all())
        self.assertTrue((df['packet_length_cv_10'] >= 0).all())
    
    def test_function_code_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20, vary_function_codes=True)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_function_code_features()
        
        fc_columns = [
            'is_read_operation', 'is_write_operation', 'is_error_response',
            'function_code_changes', 'function_code_stability_10'
        ]
        for col in fc_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue(df['is_read_operation'].isin([0, 1]).all())
        self.assertTrue(df['is_write_operation'].isin([0, 1]).all())
        self.assertTrue((df['function_code_stability_10'] >= 0).all())
        self.assertTrue((df['function_code_stability_10'] <= 1).all())
        
        self.assertTrue(any(['fc_' in col for col in df.columns]))
    
    def test_protocol_validation_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_protocol_validation_features()
        
        validation_columns = [
            'protocol_id_valid', 'unit_id_valid',
            'function_code_valid', 'length_consistent'
        ]
        for col in validation_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue(df['protocol_id_valid'].all())
        self.assertTrue(df['unit_id_valid'].all())
        self.assertTrue(df['function_code_valid'].all())
    
    def test_flow_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_flow_features()
        
        flow_columns = [
            'packets_per_src', 'packets_per_dst', 'packets_per_unit',
            'unique_src_ips', 'unique_dst_ips', 'unique_unit_ids'
        ]
        for col in flow_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue((df['packets_per_src'] > 0).all())
        self.assertTrue((df['unique_src_ips'] > 0).all())
    
    def test_derived_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        extractor.extract_all_features()
        df = extractor.extract_derived_features()
        
        self.assertIn('entropy_stability', df.columns)
        self.assertIn('read_write_ratio', df.columns)
        self.assertIn('traffic_intensity', df.columns)
        
        self.assertTrue((df['entropy_stability'] >= 0).all())
        self.assertTrue((df['entropy_stability'] <= 1).all())
    
    def test_extract_all_features_comprehensive(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_all_features()
        
        self.assertEqual(len(df), 20)
        
        self.assertGreater(len(df.columns), 30)
        
        critical_features = [
            'payload_entropy', 'time_delta_mean_10', 'function_code',
            'packet_length_mean_10', 'is_valid', 'time_delta_cv_10',
            'function_code_stability_10', 'header_entropy',
            'packet_length_cv_10', 'is_error_response'
        ]
        for feature in critical_features:
            self.assertIn(feature, df.columns)
    
    def test_feature_matrix_generation(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        extractor.extract_all_features()
        feature_matrix = extractor.get_feature_matrix()
        
        self.assertEqual(feature_matrix.shape[0], 20)
        self.assertGreater(feature_matrix.shape[1], 10)
        
        self.assertFalse(np.isnan(feature_matrix.astype(float)).any())
    
    def test_summary_statistics_completeness(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        extractor.extract_all_features()
        stats = extractor.get_summary_statistics()
        
        required_keys = [
            'total_packets', 'unique_function_codes',
            'function_code_distribution', 'packet_length',
            'timing', 'network', 'entropy', 'operations',
            'protocol_compliance'
        ]
        for key in required_keys:
            self.assertIn(key, stats)
        
        self.assertEqual(stats['total_packets'], 20)
        self.assertIn('mean', stats['packet_length'])
        self.assertIn('std', stats['packet_length'])
        self.assertIn('cv', stats['packet_length'])
        self.assertIn('mean_ms', stats['timing'])
        self.assertIn('cv', stats['timing'])
        self.assertIn('payload', stats['entropy'])
        self.assertIn('read_count', stats['operations'])
    
    def test_rolling_window_calculations(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_all_features()
        
        self.assertFalse(df['packet_length_mean_10'].isna().iloc[-1])
        self.assertFalse(df['time_delta_mean_10'].isna().iloc[-1])
        self.assertFalse(df['payload_entropy_mean_10'].isna().iloc[-1])
        
        self.assertTrue((df['packet_length_mean_10'].iloc[9:] >= df['packet_length_min_10'].iloc[9:]).all())
        self.assertTrue((df['packet_length_mean_10'].iloc[9:] <= df['packet_length_max_10'].iloc[9:]).all())
    
    def test_coefficient_of_variation(self):
        parser = self.create_mock_parser_with_packets(20, vary_timing=False)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_timing_features()
        
        cv_values = df['time_delta_cv_10'].dropna()
        self.assertTrue((cv_values >= 0).all())
        
        regular_timing_cv = cv_values.iloc[-1]
        self.assertLess(regular_timing_cv, 0.5)
    
    def test_feature_value_ranges(self):
        parser = self.create_mock_parser_with_packets(50)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_all_features()
        
        self.assertTrue((df['packet_length'] >= 12).all())
        self.assertTrue((df['packet_length'] <= 260).all())
        
        self.assertTrue((df['payload_entropy'] >= 0).all())
        self.assertTrue((df['payload_entropy'] <= 8).all())
        
        self.assertTrue((df['time_delta_ms'].dropna() >= 0).all())
        
        self.assertTrue((df['function_code'] >= 1).all())
        self.assertTrue((df['function_code'] <= 127).all())
    
    def test_anomaly_detection_features(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_all_features()
        
        self.assertIn('burst_indicator', df.columns)
        self.assertIn('is_error_response', df.columns)
        self.assertIn('is_normal_entropy', df.columns)
        
        self.assertTrue(df['burst_indicator'].isin([0, 1]).all())
        self.assertTrue(df['is_error_response'].isin([0, 1]).all())
        self.assertTrue(df['is_normal_entropy'].isin([True, False]).all())
    
    def test_entropy_calculator_functionality(self):
        calc = EntropyCalculator()
        
        uniform_data = bytes([1] * 100)
        entropy = calc.calculate_shannon_entropy(uniform_data)
        self.assertEqual(entropy, 0.0)
        
        random_data = bytes([i % 256 for i in range(256)])
        entropy = calc.calculate_shannon_entropy(random_data)
        self.assertGreater(entropy, 6.0)
        
        normal_modbus_data = bytes([0, 1, 2, 3, 4, 5] * 10)
        entropy = calc.calculate_shannon_entropy(normal_modbus_data)
        self.assertTrue(calc.is_entropy_normal(entropy, expected_range=(2.0, 6.5)))
    
    def test_feature_consistency_across_extractions(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = ModbusFeatureExtractor(parser)
        
        df1 = extractor.extract_all_features()
        df2 = extractor.extract_all_features()
        
        pd.testing.assert_frame_equal(df1, df2)
    
    def test_empty_packet_handling(self):
        class EmptyParser:
            def __init__(self):
                self.packets = []
        
        parser = EmptyParser()
        extractor = ModbusFeatureExtractor(parser)
        
        df = extractor.extract_basic_features()
        self.assertEqual(len(df), 0)
        
        stats = extractor.get_summary_statistics()
        self.assertEqual(stats['total_packets'], 0)


class TestFeatureSpecificationCompliance(unittest.TestCase):
    
    def test_all_specified_features_present(self):
        parser = TestFeatureExtraction().create_mock_parser_with_packets(50)
        extractor = ModbusFeatureExtractor(parser)
        df = extractor.extract_all_features()
        
        required_features = [
            'packet_length', 'modbus_length', 'data_length',
            'transaction_id', 'protocol_id', 'unit_id', 'function_code',
            'packet_length_mean_10', 'packet_length_std_10', 
            'packet_length_max_10', 'packet_length_min_10',
            'time_delta', 'time_delta_ms', 'time_delta_mean_10',
            'time_delta_std_10', 'time_delta_cv_10',
            'payload_entropy', 'header_entropy', 'full_packet_entropy',
            'is_read_operation', 'is_write_operation', 'is_error_response',
            'function_code_changes', 'function_code_stability_10',
            'is_valid', 'protocol_id_valid', 'unit_id_valid',
            'function_code_valid', 'length_consistent',
            'burst_indicator', 'periodicity_score', 'entropy_stability',
            'traffic_intensity', 'read_write_ratio'
        ]
        
        for feature in required_features:
            self.assertIn(feature, df.columns, f"Missing required feature: {feature}")


def run_tests():
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == '__main__':
    run_tests()