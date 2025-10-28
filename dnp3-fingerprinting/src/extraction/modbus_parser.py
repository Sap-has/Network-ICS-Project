from scapy.all import rdpcap, TCP, IP
from typing import Dict, List, Optional
import struct


class ModbusPacket:    
    def __init__(self, timestamp: float, src_ip: str, dst_ip: str, 
                 src_port: int, dst_port: int, raw_data: bytes):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.raw_data = raw_data
        
        # Modbus TCP/IP ADU fields
        self.transaction_id: Optional[int] = None
        self.protocol_id: Optional[int] = None
        self.length: Optional[int] = None
        self.unit_id: Optional[int] = None
        self.function_code: Optional[int] = None
        self.data: Optional[bytes] = None
        
        self._parse_modbus_header()
    
    def _parse_modbus_header(self):
        try:
            # Modbus TCP header is 7 bytes (MBAP header)
            # Transaction ID (2 bytes) + Protocol ID (2 bytes) + 
            # Length (2 bytes) + Unit ID (1 byte)
            if len(self.raw_data) < 7:
                return
            
            # Unpack MBAP header (big-endian format)
            self.transaction_id = struct.unpack('>H', self.raw_data[0:2])[0]
            self.protocol_id = struct.unpack('>H', self.raw_data[2:4])[0]
            self.length = struct.unpack('>H', self.raw_data[4:6])[0]
            self.unit_id = struct.unpack('B', self.raw_data[6:7])[0]
            
            # Function code is the first byte after MBAP header
            if len(self.raw_data) >= 8:
                self.function_code = struct.unpack('B', self.raw_data[7:8])[0]
                
            # Remaining data (PDU data field)
            if len(self.raw_data) > 8:
                self.data = self.raw_data[8:]
                
        except (struct.error, IndexError) as e:
            # Invalid packet structure
            pass
    
    def is_valid(self) -> bool:
        # Protocol ID should be 0 for Modbus
        # Function code should be in valid range (1-127)
        return (self.protocol_id == 0 and 
                self.function_code is not None and 
                1 <= self.function_code <= 127)
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'transaction_id': self.transaction_id,
            'protocol_id': self.protocol_id,
            'length': self.length,
            'unit_id': self.unit_id,
            'function_code': self.function_code,
            'packet_length': len(self.raw_data),
            'data_length': len(self.data) if self.data else 0,
            'is_valid': self.is_valid()
        }


class ModbusParser:    
    MODBUS_PORT = 502
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets: List[ModbusPacket] = []
    
    def parse(self) -> List[ModbusPacket]:
        print(f"Reading PCAP file: {self.pcap_file}")
        
        try:
            # Read all packets from PCAP
            pcap_packets = rdpcap(self.pcap_file)
            print(f"Total packets in PCAP: {len(pcap_packets)}")
            
            modbus_count = 0
            
            # Filter and parse Modbus TCP packets
            for pkt in pcap_packets:
                # Check if packet has TCP layer
                if TCP not in pkt:
                    continue
                
                # Check if packet is on Modbus port (502)
                tcp_layer = pkt[TCP]
                if tcp_layer.dport != self.MODBUS_PORT and tcp_layer.sport != self.MODBUS_PORT:
                    continue
                
                # Extract IP information
                if IP in pkt:
                    ip_layer = pkt[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                else:
                    # Skip packets without IP layer
                    continue
                
                # Extract TCP payload (Modbus data)
                payload = bytes(tcp_layer.payload)
                
                if len(payload) > 0:
                    modbus_pkt = ModbusPacket(
                        timestamp=float(pkt.time),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=tcp_layer.sport,
                        dst_port=tcp_layer.dport,
                        raw_data=payload
                    )
                    
                    # Only keep valid Modbus packets
                    if modbus_pkt.is_valid():
                        self.packets.append(modbus_pkt)
                        modbus_count += 1
            
            print(f"Valid Modbus TCP packets extracted: {modbus_count}")
            return self.packets
            
        except FileNotFoundError:
            print(f"Error: PCAP file not found: {self.pcap_file}")
            return []
        except Exception as e:
            print(f"Error parsing PCAP file: {e}")
            return []
    
    def get_packet_count(self) -> int:
        return len(self.packets)
    
    def get_packets_as_dicts(self) -> List[Dict]:
        return [pkt.to_dict() for pkt in self.packets]
    
    def filter_by_function_code(self, function_code: int) -> List[ModbusPacket]:
        return [pkt for pkt in self.packets if pkt.function_code == function_code]
    
    def get_unique_function_codes(self) -> List[int]:
        return sorted(list(set(pkt.function_code for pkt in self.packets 
                              if pkt.function_code is not None)))


# Function code descriptions for reference
MODBUS_FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    23: "Read/Write Multiple Registers"
}


def decode_function_code(code: int) -> str:
    if code in MODBUS_FUNCTION_CODES:
        return MODBUS_FUNCTION_CODES[code]
    elif code >= 128:
        return f"Error Response (Exception Code: {code - 128})"
    else:
        return f"Unknown Function Code: {code}"