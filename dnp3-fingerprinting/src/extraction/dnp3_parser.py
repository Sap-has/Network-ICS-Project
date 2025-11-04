from scapy.all import rdpcap, TCP, IP
from typing import Dict, List, Optional
import struct


class DNP3Packet:
    def __init__(self, timestamp: float, src_ip: str, dst_ip: str, 
                 src_port: int, dst_port: int, raw_data: bytes):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.raw_data = raw_data
        
        self.transaction_id: Optional[int] = None
        self.protocol_id: Optional[int] = None
        self.length: Optional[int] = None
        self.unit_id: Optional[int] = None
        self.function_code: Optional[int] = None
        self.data: Optional[bytes] = None
        
        self._parse_dnp3_header()
    
    def _parse_dnp3_header(self):
        try:
            if len(self.raw_data) < 10:
                return
            
            if self.raw_data[0:2] != b'\x05\x64':
                return
            
            self.length = struct.unpack('B', self.raw_data[2:3])[0]
            control = struct.unpack('B', self.raw_data[3:4])[0]
            dest = struct.unpack('<H', self.raw_data[4:6])[0]
            src = struct.unpack('<H', self.raw_data[6:8])[0]
            
            self.unit_id = dest
            self.transaction_id = src
            self.protocol_id = 0
            
            if len(self.raw_data) >= 11:
                self.function_code = struct.unpack('B', self.raw_data[10:11])[0]
                
            if len(self.raw_data) > 11:
                self.data = self.raw_data[11:]
                
        except (struct.error, IndexError):
            pass
    
    def is_valid(self) -> bool:
        return (self.raw_data[0:2] == b'\x05\x64' and 
                self.function_code is not None and 
                0 <= self.function_code <= 255)
    
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


class DNP3Parser:
    DNP3_PORT = 20000
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets: List[DNP3Packet] = []
    
    def parse(self) -> List[DNP3Packet]:
        print(f"Reading PCAP file: {self.pcap_file}")
        
        try:
            pcap_packets = rdpcap(self.pcap_file)
            print(f"Total packets in PCAP: {len(pcap_packets)}")
            
            dnp3_count = 0
            
            for pkt in pcap_packets:
                if TCP not in pkt:
                    continue
                
                tcp_layer = pkt[TCP]
                if tcp_layer.dport != self.DNP3_PORT and tcp_layer.sport != self.DNP3_PORT:
                    continue
                
                if IP in pkt:
                    ip_layer = pkt[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                else:
                    continue
                
                payload = bytes(tcp_layer.payload)
                
                if len(payload) > 0 and payload[0:2] == b'\x05\x64':
                    dnp3_pkt = DNP3Packet(
                        timestamp=float(pkt.time),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=tcp_layer.sport,
                        dst_port=tcp_layer.dport,
                        raw_data=payload
                    )
                    
                    if dnp3_pkt.is_valid():
                        self.packets.append(dnp3_pkt)
                        dnp3_count += 1
            
            print(f"Valid DNP3 packets extracted: {dnp3_count}")
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
    
    def filter_by_function_code(self, function_code: int) -> List[DNP3Packet]:
        return [pkt for pkt in self.packets if pkt.function_code == function_code]
    
    def get_unique_function_codes(self) -> List[int]:
        return sorted(list(set(pkt.function_code for pkt in self.packets 
                              if pkt.function_code is not None)))


DNP3_FUNCTION_CODES = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NO_ACK",
    7: "FREEZE",
    8: "FREEZE_NO_ACK",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE"
}


def decode_function_code(code: int) -> str:
    if code in DNP3_FUNCTION_CODES:
        return DNP3_FUNCTION_CODES[code]
    elif code >= 128:
        return f"Response (Code: {code})"
    else:
        return f"Unknown Function Code: {code}"