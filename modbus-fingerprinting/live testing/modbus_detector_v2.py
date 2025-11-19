#!/usr/bin/env python3
"""
modbus_detector_v2.py

Adaptive Modbus detector v2
- Uses EWMA baselines for packet-rate (global and per flow)
- Dynamic flood threshold = mean + k * std (all EWMA-based)
- Detects malformed and invalid-field packets
- Detects scan (many unit_ids within a window)
- Detects replay (repeated raw payloads)
- Aggregates suspicious packets into attack sessions and writes JSON reports
"""

import time, os, threading, json, argparse, math, hashlib
from collections import defaultdict, deque, Counter
from scapy.all import sniff, Raw

# Defaults
DEFAULT_IFACE = "lo"
DEFAULT_PORT = 5020
REPORT_DIR = "reports_v2"
os.makedirs(REPORT_DIR, exist_ok=True)

# EWMA helper for mean & variance (exponentially weighted)
class EWStats:
    def __init__(self, alpha=0.2):
        self.alpha = alpha
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    def update(self, x):
        x = float(x)
        if self.n == 0:
            # bootstrap
            self.mean = x
            self.var = 0.0
            self.n = 1
            return
        a = self.alpha
        m0 = self.mean
        # EW mean
        self.mean = (1-a)*self.mean + a*x
        # EW variance (B. West method)
        self.var = (1-a)*(self.var + a*(x - m0)*(x - m0))
        self.n += 1

    def z(self, x):
        if self.n == 0 or self.var <= 1e-12:
            return 0.0
        return (x - self.mean) / math.sqrt(self.var)

    def std(self):
        return math.sqrt(self.var) if self.var > 0 else 0.0

class AttackSession:
    def __init__(self):
        self.start = None
        self.end = None
        self.events = []
        self.counts = Counter()
        self.unit_ids = set()
        self.raw_hashes = Counter()
        self.timestamps = deque()

    def add_event(self, evt):
        now = time.time()
        if self.start is None:
            self.start = now
        self.end = now
        self.events.append(evt)
        self.counts[evt["category"]] += 1
        if evt.get("unit") is not None:
            self.unit_ids.add(evt["unit"])
        if evt.get("raw_hex"):
            self.raw_hashes[hashlib.sha1(evt["raw_hex"].encode()).hexdigest()] += 1
        self.timestamps.append(now)
        # keep timestamp window small (for pps calculation)
        while self.timestamps and now - self.timestamps[0] > 2.0:
            self.timestamps.popleft()

    def pps(self):
        if len(self.timestamps) < 2:
            return 0.0
        window = (self.timestamps[-1] - self.timestamps[0]) or 1e-6
        return len(self.timestamps) / window

    def summarize(self):
        s = {
            "start": self.start,
            "end": self.end,
            "duration_s": (self.end - self.start) if (self.start and self.end) else 0.0,
            "counts": dict(self.counts),
            "distinct_units": len(self.unit_ids),
            "top_repeats": self.raw_hashes.most_common(5),
            "pps": self.pps()
        }
        cats = []
        if s["pps"] >= 1:  # placeholder; real rule added later
            pass
        if self.counts.get("malformed",0) > 0:
            cats.append("malformed")
        if self.counts.get("invalid_field",0) > 0:
            cats.append("invalid_field")
        if len(self.unit_ids) >= 8:
            cats.append("scan")
        if any(v>1 for v in self.raw_hashes.values()):
            cats.append("replay")
        if s["pps"] > 50:
            cats.append("flood")
        if not cats:
            cats = ["suspicious"]
        s["inferred_categories"] = cats
        return s

    def dump(self):
        summary = self.summarize()
        report = {
            "start_ts": summary["start"],
            "end_ts": summary["end"],
            "duration_s": summary["duration_s"],
            "counts": summary["counts"],
            "distinct_units": summary["distinct_units"],
            "pps": summary["pps"],
            "inferred_categories": summary["inferred_categories"],
            "events_sample": self.events[:200]
        }
        fn = os.path.join(REPORT_DIR, f"report_{int(time.time())}.json")
        with open(fn, "w") as f:
            json.dump(report, f, indent=2)
        print("Wrote report:", fn)
        return fn

class DetectorV2:
    def __init__(self, iface="lo", port=5020, alpha=0.2, quiet_ttl=4.0, flood_k=4.0):
        self.iface = iface
        self.port = port
        self.alpha = alpha
        self.quiet_ttl = quiet_ttl
        self.flood_k = flood_k

        # baseline EWMA for global PPS
        self.global_pps = EWStats(alpha=self.alpha)
        # short window counters to measure recent pps per second
        self.sec_window = deque()  # timestamps of recent packets (global)
        # per-flow EWMA baseline (flow key: src>dst:unit)
        self.flow_stats = defaultdict(lambda: EWStats(alpha=self.alpha))

        # replay detection (small cache of recent payload hashes)
        self.recent_hashes = Counter()
        self.hash_window = deque(maxlen=1000)

        # active attack session
        self.current_session = None
        self.last_suspicious = None
        self.lock = threading.Lock()

    def push_global_pkt_time(self, now):
        self.sec_window.append(now)
        # remove older than 1s window for instant pps
        while self.sec_window and now - self.sec_window[0] > 1.0:
            self.sec_window.popleft()
        pps = len(self.sec_window)
        # update global EWMA stats for pps
        self.global_pps.update(pps)
        return pps

    def push_flow_pkt(self, flow_key, now, pps_value):
        # update per-flow EWMA using pps_value
        self.flow_stats[flow_key].update(pps_value)

    def parse_mbap(self, raw):
        if len(raw) < 8:
            return {"malformed":True, "reasons":["too_short"]}
        trans = int.from_bytes(raw[0:2],"big")
        proto = int.from_bytes(raw[2:4],"big")
        length = int.from_bytes(raw[4:6],"big")
        unit = raw[6]
        func = raw[7] if len(raw) > 7 else None
        reasons = []
        suspicious = False
        category = None
        if proto != 0:
            suspicious=True; reasons.append("proto_not_zero"); category="invalid_field"
        if not (0 <= unit <= 247):
            suspicious=True; reasons.append("unit_out_of_range"); category="invalid_field"
        if func is None or not (1 <= func <= 126):
            suspicious=True; reasons.append("invalid_func"); if category is None: category="invalid_field"
        if length == 0 or length > 260:
            suspicious=True; reasons.append("length_suspicious"); if category is None: category="malformed"
        tail_len = len(raw) - 6
        if length > tail_len:
            suspicious=True; reasons.append("length_larger_than_captured"); if category is None: category="malformed"
        return {
            "suspicious": suspicious,
            "category": category or ("anomalous" if suspicious else "normal"),
            "reasons": reasons,
            "trans": trans, "proto": proto, "length": length, "unit": unit, "func": func
        }

    def on_packet(self, pkt):
        if not pkt.haslayer(Raw):
            return
        now = time.time()
        raw = bytes(pkt[Raw])
        # update instant pps
        pps_instant = self.push_global_pkt_time(now)
        # build flow key
        try:
            src = pkt[0][1].src
            dst = pkt[0][1].dst
        except Exception:
            src = "?"
            dst = "?"
        # fake unit key if unknown later
        parsed = self.parse_mbap(raw)
        flow_key = f"{src}>{dst}:{parsed.get('unit')}"
        # update per-flow baseline using instant pps
        self.push_flow_pkt(flow_key, now, pps_instant)

        # replay detection using short raw hash memory
        raw_hex = raw.hex()
        h = hashlib.sha1(raw_hex.encode()).hexdigest()
        self.hash_window.append(h)
        self.recent_hashes[h] += 1
        # if count > 1, it's repeat
        if self.recent_hashes[h] > 1:
            parsed["suspicious"] = True
            parsed["reasons"].append("replay_detected")
            parsed["category"] = parsed.get("category") or "replay"

        # dynamic flood detection: compare instant pps to EWMA baseline
        g_mean = self.global_pps.mean
        g_std = self.global_pps.std()
        # if std is 0 (cold start), use small base
        threshold = g_mean + max(2.0, self.flood_k * g_std)
        if pps_instant >= max(10, threshold):  # ensure threshold not tiny
            parsed["suspicious"] = True
            parsed["reasons"].append("flood_rate_high")
            parsed["category"] = parsed.get("category") or "flood"

        # scan detection: many distinct units seen in current session window
        # We implement check inside session aggregation below

        # if suspicious, record it
        if parsed["suspicious"]:
            evt = {
                "ts": now,
                "category": parsed["category"],
                "reasons": parsed["reasons"],
                "unit": parsed.get("unit"),
                "func": parsed.get("func"),
                "raw_hex": raw_hex
            }
            with self.lock:
                if self.current_session is None:
                    self.current_session = AttackSession()
                self.current_session.add_event(evt)
                self.last_suspicious = now
        # cleanup/reduce recent_hashes size occasionally
        if len(self.hash_window) > 800:
            # rebuild Counter to keep memory bounded
            self.recent_hashes = Counter(self.hash_window)

    def monitor_loop(self):
        while True:
            time.sleep(1.0)
            with self.lock:
                if self.current_session and self.last_suspicious:
                    if time.time() - self.last_suspicious > self.quiet_ttl:
                        # finalize session
                        self.current_session.end = self.last_suspicious
                        # compute additional classification using EWMA baselines
                        summ = self.current_session.summarize()
                        # dynamic flood: compare session pps to global EWMA
                        if summ["pps"] > (self.global_pps.mean + self.flood_k * self.global_pps.std()):
                            if "flood" not in summ["inferred_categories"]:
                                summ["inferred_categories"].append("flood")
                        # scan detection: if many distinct units
                        if summ["distinct_units"] >= 8 and "scan" not in summ["inferred_categories"]:
                            summ["inferred_categories"].append("scan")
                        # dump report
                        self.current_session.dump()
                        # reset
                        self.current_session = None
                        self.last_suspicious = None

    def start(self):
        # monitor thread
        t = threading.Thread(target=self.monitor_loop, daemon=True)
        t.start()
        bpf = f"tcp port {self.port}"
        print(f"Starting detector on {self.iface} (filter: {bpf})")
        try:
            sniff(iface=self.iface, filter=bpf, prn=self.on_packet, store=False)
        except PermissionError:
            print("Run with sudo/root to sniff interfaces.")
        except KeyboardInterrupt:
            print("Stopped by user.")
            # flush current session if any
            with self.lock:
                if self.current_session:
                    self.current_session.dump()

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=DEFAULT_IFACE)
    ap.add_argument("--port", default=DEFAULT_PORT, type=int)
    ap.add_argument("--alpha", default=0.2, type=float, help="EWMA alpha")
    ap.add_argument("--quiet_ttl", default=4.0, type=float, help="seconds of silence to close session")
    ap.add_argument("--flood_k", default=4.0, type=float, help="threshold multiplier for flood (k*std)")
    return ap.parse_args()

if __name__ == "__main__":
    args = parse_args()
    det = DetectorV2(iface=args.iface, port=args.port, alpha=args.alpha, quiet_ttl=args.quiet_ttl, flood_k=args.flood_k)
    try:
        det.start()
    except KeyboardInterrupt:
        print("Detector stopped.")
