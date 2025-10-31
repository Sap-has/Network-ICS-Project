from scapy.all import sniff, Raw
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
import json, time

LOG_JSON = "modbus_log.jsonl"

#Optional txt file output:
#LOG_TXT  = "modbus_log.txt"

def log_event(event):
    with open(LOG_JSON, "a") as jf:
        jf.write(json.dumps(event) + "\n")
    with open(LOG_TXT, "a") as tf:
        tf.write(f"{event['timestamp']} | {event['status']} | func={event['func']} unit={event['unit']} reasons={event['reasons']}\n")

def detect(pkt):
    func = unit = proto = None
    bad = []
    
    # Try Scapy’s Modbus layer first
    if pkt.haslayer(ModbusADURequest) or pkt.haslayer(ModbusADUResponse):
        adu = pkt[ModbusADURequest] if pkt.haslayer(ModbusADURequest) else pkt[ModbusADUResponse]
        func  = getattr(adu, "funcCode", None)
        unit  = getattr(adu, "unitId", None)
        proto = getattr(adu, "protoId", None)

    # Fallback: parse raw payload
    elif pkt.haslayer(Raw):
        data = bytes(pkt[Raw])
        if len(data) >= 8:
            proto = int.from_bytes(data[2:4], "big")
            unit  = data[6]
            func  = data[7]

    # Apply rules
    if proto is not None and proto != 0:
        bad.append("Invalid Protocol ID")
    if unit is not None and not (0 <= unit <= 247):
        bad.append("Unit ID out of range")
    if func is not None and func not in range(1,127):
        bad.append("Reserved/Unknown Function Code")

    status = "ALERT" if bad else "OK"

    event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "func": func,
        "unit": unit,
        "reasons": bad
    }

    if bad:
        print(f"[ALERT] Bad Modbus packet func={func}, unit={unit}, reasons={bad}")
    else:
        print(f"[OK] Modbus packet func={func}, unit={unit}")

    log_event(event)

print("Sniffing Modbus traffic on loopback:5020...")
sniff(iface="lo", filter="tcp port 5020", prn=detect, store=False)

