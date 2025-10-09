import unittest
import struct

from src.extraction.modbus_parser import ModbusPacket, ModbusParser, decode_function_code
from src.extraction.feature_extracter import ModbusFeatureExtractor


class TestModbusPacket(unittest.TestCase):
    def create_sample_modbus_packet(self, function_code=3):
        # Create Modbus TCP packet: Read Holding Registers (FC=3)
        # MBAP Header: Transaction ID, Protocol ID, Length, Unit ID
        transaction_id = struct.pack('>H', 1)  # Transaction ID = 1
        protocol_id = struct.pack('>H', 0)     # Protocol ID = 0 (Modbus)
        length = struct.pack('>H', 6)          # Length = 6 bytes following
        unit_id = struct.pack('B', 1)          # Unit ID = 1
        
        # PDU: Function Code + Data
        fc = struct.pack('B', function_code)
        data = struct.pack('>HH', 0, 10)       # Starting address=0, Quantity=10
        
        raw_data = transaction_id + protocol_id + length + unit_id + fc + data
        
        return ModbusPacket(
            timestamp=1234567890.0,
            src_ip="192.168.1.100",
            dst_ip="192.168.1.10",
            src_port=50000,
            dst_port=502,
            raw_data=raw_data
        )
    
    def test_packet_parsing(self):
        pkt = self.create_sample_modbus_packet()
        
        self.assertEqual(pkt.transaction_id, 1)
        self.assertEqual(pkt.protocol_id, 0)
        self.assertEqual(pkt.length, 6)
        self.assertEqual(pkt.unit_id, 1)
        self.assertEqual(pkt.function_code, 3)
        self.assertTrue(pkt.is_valid())
    
    def test_packet_validation(self):
        # Valid packet
        pkt = self.create_sample_modbus_packet()
        self.assertTrue(pkt.is_valid())
        
        # Invalid packet (wrong protocol ID)
        raw_data = struct.pack('>HHHBB', 1, 999, 6, 1, 3)  # Protocol ID = 999
        pkt_invalid = ModbusPacket(1.0, "192.168.1.1", "192.168.1.2", 
                                   50000, 502, raw_data)
        self.assertFalse(pkt_invalid.is_valid())
    
    def test_to_dict(self):
        pkt = self.create_sample_modbus_packet()
        pkt_dict = pkt.to_dict()
        
        self.assertIn('transaction_id', pkt_dict)
        self.assertIn('function_code', pkt_dict)
        self.assertIn('packet_length', pkt_dict)
        self.assertEqual(pkt_dict['function_code'], 3)
        self.assertTrue(pkt_dict['is_valid'])
    
    def test_different_function_codes(self):
        test_codes = [1, 2, 3, 4, 5, 6, 15, 16]
        
        for code in test_codes:
            pkt = self.create_sample_modbus_packet(function_code=code)
            self.assertEqual(pkt.function_code, code)
            self.assertTrue(pkt.is_valid())


class TestModbusParser(unittest.TestCase):    
    def test_function_code_decoder(self):
        self.assertEqual(decode_function_code(1), "Read Coils")
        self.assertEqual(decode_function_code(3), "Read Holding Registers")
        self.assertEqual(decode_function_code(16), "Write Multiple Registers")
        self.assertIn("Unknown", decode_function_code(99))
        self.assertIn("Error Response", decode_function_code(131))


class TestFeatureExtractor(unittest.TestCase):
    def create_mock_parser(self):
        """Create a mock parser with sample packets"""
        class MockParser:
            def __init__(self):
                self.packets = []
                # Add some sample packets
                for i in range(5):
                    raw_data = struct.pack('>HHHBB', i, 0, 6, 1, 3)
                    pkt = ModbusPacket(
                        timestamp=1234567890.0 + i,
                        src_ip="192.168.1.100",
                        dst_ip="192.168.1.10",
                        src_port=50000,
                        dst_port=502,
                        raw_data=raw_data
                    )
                    self.packets.append(pkt)
        
        return MockParser()
    
    def test_basic_feature_extraction(self):
        parser = self.create_mock_parser()
        extractor = ModbusFeatureExtractor(parser)
        
        features_df = extractor.extract_basic_features()
        
        self.assertEqual(len(features_df), 5)
        self.assertIn('function_code', features_df.columns)
        self.assertIn('packet_length', features_df.columns)
        self.assertIn('transaction_id', features_df.columns)
    
    def test_statistical_features(self):
        parser = self.create_mock_parser()
        extractor = ModbusFeatureExtractor(parser)
        
        features_df = extractor.extract_statistical_features()
        
        self.assertIn('time_delta', features_df.columns)
        self.assertIn('packet_length_mean_10', features_df.columns)
    
    def test_get_feature_matrix(self):
        parser = self.create_mock_parser()
        extractor = ModbusFeatureExtractor(parser)
        
        extractor.extract_all_features()
        feature_matrix = extractor.get_feature_matrix()
        
        self.assertEqual(feature_matrix.shape[0], 5)  # 5 packets
        self.assertGreater(feature_matrix.shape[1], 0)  # Multiple features
    
    def test_summary_statistics(self):
        parser = self.create_mock_parser()
        extractor = ModbusFeatureExtractor(parser)
        
        extractor.extract_basic_features()
        stats = extractor.get_summary_statistics()
        
        self.assertIn('total_packets', stats)
        self.assertEqual(stats['total_packets'], 5)
        self.assertIn('unique_function_codes', stats)


def run_tests():
    """Run all unit tests"""
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == '__main__':
    run_tests()