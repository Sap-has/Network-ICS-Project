import unittest
import struct
import numpy as np
import pandas as pd
from src.extraction.dnp3_parser import DNP3Packet, DNP3Parser
from src.extraction.feature_extractor import DNP3FeatureExtractor
from src.extraction.entropy_calculator import EntropyCalculator


class TestDNP3FeatureExtraction(unittest.TestCase):
    
    def create_mock_parser_with_packets(self, num_packets=20, vary_timing=True, vary_function_codes=True):
        class MockParser:
            def __init__(self):
                self.packets = []
        
        parser = MockParser()
        base_time = 1234567890.0
        
        for i in range(num_packets):
            start_bytes = b'\x05\x64'
            length = struct.pack('B', 10)
            control = struct.pack('B', 0x44)
            dest = struct.pack('<H', (i % 5) + 1)
            src = struct.pack('<H', i)
            crc = b'\x00\x00'
            
            if vary_function_codes:
                fc_options = [0, 1, 2, 129]
                fc = struct.pack('B', fc_options[i % len(fc_options)])
            else:
                fc = struct.pack('B', 1)
            
            data = struct.pack('>HH', 0, 10)
            raw_data = start_bytes + length + control + dest + src + crc + fc + data
            
            if vary_timing:
                time_offset = i * 0.1 + (i % 3) * 0.02
            else:
                time_offset = i * 0.1
            
            pkt = DNP3Packet(
                timestamp=base_time + time_offset,
                src_ip="192.168.1.100",
                dst_ip=f"192.168.1.{10 + (i % 3)}",
                src_port=50000,
                dst_port=20000,
                raw_data=raw_data
            )
            parser.packets.append(pkt)
        
        return parser
    
    def test_basic_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = DNP3FeatureExtractor(parser)
        
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
    
    def test_entropy_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = DNP3FeatureExtractor(parser)
        
        df = extractor.extract_entropy_features()
        
        entropy_columns = [
            'payload_entropy', 'header_entropy', 'full_packet_entropy',
            'payload_entropy_mean_10', 'payload_entropy_std_10'
        ]
        for col in entropy_columns:
            self.assertIn(col, df.columns)
        
        self.assertTrue((df['payload_entropy'] >= 0).all())
        self.assertTrue((df['payload_entropy'] <= 8).all())
    
    def test_timing_features_extraction(self):
        parser = self.create_mock_parser_with_packets(20, vary_timing=True)
        extractor = DNP3FeatureExtractor(parser)
        
        df = extractor.extract_timing_features()
        
        timing_columns = [
            'time_delta', 'time_delta_ms',
            'time_delta_mean_10', 'time_delta_cv_10'
        ]
        for col in timing_columns:
            self.assertIn(col, df.columns)
    
    def test_extract_all_features(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = DNP3FeatureExtractor(parser)
        
        df = extractor.extract_all_features()
        
        self.assertEqual(len(df), 20)
        self.assertGreater(len(df.columns), 30)
    
    def test_summary_statistics(self):
        parser = self.create_mock_parser_with_packets(20)
        extractor = DNP3FeatureExtractor(parser)
        
        extractor.extract_all_features()
        stats = extractor.get_summary_statistics()
        
        required_keys = [
            'total_packets', 'unique_function_codes',
            'function_code_distribution', 'packet_length',
            'timing', 'network'
        ]
        for key in required_keys:
            self.assertIn(key, stats)
    
    def test_empty_packet_handling(self):
        class EmptyParser:
            def __init__(self):
                self.packets = []
        
        parser = EmptyParser()
        extractor = DNP3FeatureExtractor(parser)
        
        df = extractor.extract_basic_features()
        self.assertEqual(len(df), 0)


def run_tests():
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == '__main__':
    run_tests()