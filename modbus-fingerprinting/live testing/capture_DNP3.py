#!/usr/bin/env python3
"""
capture_DNP3.py — Minimal DNP3/TCP sniffer and anomaly detector (JSON-only logging)

Captures DNP3 traffic (default port 20000), extracts link-layer fields, and logs
parsed events with anomaly indicators to a JSONL file (one JSON per line).
"""

from scapy.all import sniff, Raw
import time, json, argparse, os

def parse_dnp3(payload):
    """Parse minimal DNP3 link header; return dict with any anomalies detected."""
    result = {
        "is_dnp3": False,
        "issues": [],
        "payload_len": len(payload)
    }

    # DNP3 starts with 0x05 0x64
    if len(payload) < 2:
        result["issues"].append("too_short")
        return result

    start_bytes = payload[:2]
    if start_bytes != b"\x05\x64":
        result["issues"].append("missing_start_bytes")
        return result

    result["is_dnp3"] = True

    # Minimal link header length = 8 bytes
    if len(payload) < 8:
        result["issues"].append("truncated_link_header")
        return result

    length = payload[2]
    control = payload[3]
    dest = int.from_bytes(payload[4:6], "little")
    src = int.from_bytes(payload[6:8], "little")

    result.update({
        "length": length,
        "control": control,
        "dest": dest,
        "src": src,
    })

    # sanity checks
    if length == 0:
        result["issues"].append("zero_length_field")
    if length > 250:
        result["issues"].append("length_unusually_large")
    if length > len(payload) - 3:
        result["issues"].append("length_field_larger_than_payload")

    return result


def log_event(event, json_path):
    """Append a single JSON event line."""
    with open(json_path, "a") as jf:
        jf.write(json.dumps(event) + "\n")


def handle_packet(pkt, json_path):
    """Process each captured packet."""
    if not pkt.haslayer(Raw):
        return
    payload = bytes(pkt[Raw])

    parsed = parse_dnp3(payload)
    event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "epoch": time.time(),
        "payload_len": parsed.get("payload_len"),
        "is_dnp3": parsed.get("is_dnp3"),
        "length": parsed.get("length"),
        "control": parsed.get("control"),
        "dest": parsed.get("dest"),
        "src": parsed.get("src"),
        "issues": parsed.get("issues"),
        "status": "ALERT" if parsed.get("issues") else "OK",
    }
    log_event(event, json_path)


def main():
    parser = argparse.ArgumentParser(description="DNP3/TCP live sniffer (JSON-only)")
    parser.add_argument("--iface", default="lo", help="Network interface (default: lo)")
    parser.add_argument("--port", type=int, default=20000, help="TCP port (default: 20000)")
    parser.add_argument("--json", default="dnp3_log.jsonl", help="Output JSONL file")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
    print(f"Capturing DNP3 traffic on iface={args.iface}, port={args.port}")
    print(f"Logging events to {args.json}")

    try:
        sniff(
            iface=args.iface,
            filter=f"tcp port {args.port}",
            prn=lambda pkt: handle_packet(pkt, args.json),
            store=False
        )
    except PermissionError:
        print("Permission denied — try running with sudo.")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print("Sniffer error:", e)


if __name__ == "__main__":
    main()
