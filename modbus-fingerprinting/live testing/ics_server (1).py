
import socket
import threading
import datetime
import signal
import sys
import random
from typing import Dict, Any, Tuple, Optional

# -------------------- CONFIG --------------------

DEFAULT_MODBUS_PORT = 1502  # 502 is standard but usually requires root
DEFAULT_DNP3_PORT = 20000
RECV_BUFFER = 4096
ATTACK_GAP_SECONDS = 5.0  # seconds of silence before a new attack session
LOG_FILE = "server_report.log"  # single pretty, colorized log file

# ANSI colors
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"


class AttackTracker:
    """
    Tracks ongoing attack sessions per (client_ip, protocol, attack_type).
    Groups related packets into sessions and computes how long each session lasts.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # key: (client_ip, protocol, attack_type) -> dict with start, last_seen, session_id
        self._sessions: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._next_session_id = 1

    def update(self, client_ip: str, protocol: str, attack_type: str, now: datetime.datetime) -> Dict[str, Any]:
        """
        Update or create an attack session for a given (IP, protocol, attack type).
        Returns a dictionary with session metadata including duration.
        """
        key = (client_ip, protocol, attack_type)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                # start a new session
                session_id = self._next_session_id
                self._next_session_id += 1
                session = {
                    "session_id": session_id,
                    "start": now,
                    "last_seen": now,
                }
                self._sessions[key] = session
            else:
                # if the gap between packets is big, treat it as a new session
                gap = (now - session["last_seen"]).total_seconds()
                if gap > ATTACK_GAP_SECONDS:
                    session_id = self._next_session_id
                    self._next_session_id += 1
                    session = {
                        "session_id": session_id,
                        "start": now,
                        "last_seen": now,
                    }
                    self._sessions[key] = session
                else:
                    session["last_seen"] = now

            duration = (session["last_seen"] - session["start"]).total_seconds()
            return {
                "session_id": session["session_id"],
                "session_start": session["start"].isoformat() + "Z",
                "session_last_seen": session["last_seen"].isoformat() + "Z",
                "session_duration_seconds": duration,
            }


class ICSMonitoringServer:
    """
    Multi-protocol ICS monitoring server.

    - Listens for Modbus TCP and DNP3 over TCP.
    - Handles multiple clients concurrently via threads.
    - Parses packets enough to understand what they are doing.
    - Classifies attacks and tracks attack sessions.
    - Writes a single pretty, colorized log file for analysts.
    """

    def __init__(
        self,
        modbus_port: int = DEFAULT_MODBUS_PORT,
        dnp3_port: int = DEFAULT_DNP3_PORT,
    ):
        self.modbus_port = modbus_port
        self.dnp3_port = dnp3_port

        self._shutdown_event = threading.Event()
        self._log_lock = threading.Lock()
        self._attack_tracker = AttackTracker()

        self._modbus_sock: Optional[socket.socket] = None
        self._dnp3_sock: Optional[socket.socket] = None

        # Session metadata
        self.session_id = random.randint(10000, 99999)
        self.session_start = datetime.datetime.utcnow()

    # ========================= PUBLIC METHODS =========================

    def start(self):
        """
        Start the server: binds sockets, writes a session header,
        starts accept loops for Modbus and DNP3, and waits until shutdown.
        """
        # Set up signal handler so Ctrl+C stops gracefully
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        self._modbus_sock = self._create_listen_socket(self.modbus_port)
        self._dnp3_sock = self._create_listen_socket(self.dnp3_port)

        # Write session header to the log
        self._write_session_header()

        print(f"[+] Server listening on:")
        print(f"    Modbus TCP : 0.0.0.0:{self.modbus_port}")
        print(f"    DNP3 TCP   : 0.0.0.0:{self.dnp3_port}")
        print(f"[+] Logging analyst report to: {LOG_FILE}")
        print("[+] Press Ctrl+C to stop.\n")

        threads = []
        threads.append(threading.Thread(target=self._accept_loop, args=(self._modbus_sock, "modbus"), daemon=True))
        threads.append(threading.Thread(target=self._accept_loop, args=(self._dnp3_sock, "dnp3"), daemon=True))

        for t in threads:
            t.start()

        # Wait until shutdown is requested
        try:
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(timeout=1.0)
        finally:
            print("\n[!] Shutting down server...")
            if self._modbus_sock:
                self._modbus_sock.close()
            if self._dnp3_sock:
                self._dnp3_sock.close()
            # Write session footer
            self._write_session_footer()

    # ========================= INTERNAL SERVER METHODS =========================

    def _handle_signal(self, signum, frame):
        """
        Signal handler to allow clean shutdown with Ctrl+C.
        """
        print(f"\n[!] Caught signal {signum}, stopping...")
        self._shutdown_event.set()

    def _create_listen_socket(self, port: int) -> socket.socket:
        """
        Create and return a listening TCP socket on the given port.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen()
        return s

    def _accept_loop(self, listen_sock: socket.socket, protocol: str):
        """
        Accept loop for each protocol. For each incoming connection, spawn a handler thread.
        """
        while not self._shutdown_event.is_set():
            try:
                listen_sock.settimeout(1.0)
                conn, addr = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # socket closed during shutdown
                break

            ip, port = addr
            print(f"[+] New {protocol.upper()} connection from {ip}:{port}")
            t = threading.Thread(
                target=self._client_loop,
                args=(conn, addr, protocol),
                daemon=True,
            )
            t.start()

    def _client_loop(self, conn: socket.socket, addr, protocol: str):
        """
        Per-client loop: receive data, parse packet depending on protocol,
        classify attacks, and log events.
        """
        ip, port = addr
        with conn:
            while not self._shutdown_event.is_set():
                try:
                    data = conn.recv(RECV_BUFFER)
                except ConnectionResetError:
                    print(f"[!] Connection reset by {ip}:{port}")
                    break
                except OSError:
                    break

                if not data:
                    print(f"[-] {protocol.upper()} client disconnected: {ip}:{port}")
                    break

                now = datetime.datetime.utcnow()
                timestamp = now.isoformat() + "Z"

                if protocol == "modbus":
                    parsed, attack = self._handle_modbus_packet(data, ip, port, now)
                else:
                    parsed, attack = self._handle_dnp3_packet(data, ip, port, now)

                event: Dict[str, Any] = {
                    "timestamp": timestamp,
                    "client": {
                        "ip": ip,
                        "port": port,
                    },
                    "protocol": protocol,
                    "summary": parsed.get("summary", ""),
                    "raw": {
                        "length": len(data),
                        "hex_preview": data[:32].hex(),
                    },
                    "parsed": parsed,
                    "attack": attack,
                }

                self._log_event(event)

    # ========================= MODBUS HANDLING =========================

    def _handle_modbus_packet(
        self,
        data: bytes,
        ip: str,
        port: int,
        now: datetime.datetime,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Basic Modbus TCP parser and attack classifier.
        """
        parsed: Dict[str, Any] = {
            "valid": False,
            "summary": "Modbus packet (unparsed)",
        }
        attack: Dict[str, Any] = {
            "is_attack": False,
            "type": "none",
        }

        try:
            if len(data) < 8:
                parsed["summary"] = "Too short to be valid Modbus TCP."
                return parsed, attack

            transaction_id = int.from_bytes(data[0:2], "big")
            protocol_id = int.from_bytes(data[2:4], "big")
            length_field = int.from_bytes(data[4:6], "big")
            unit_id = data[6]
            func_code = data[7]

            pdu = data[7:]
            parsed.update({
                "valid": True,
                "transaction_id": transaction_id,
                "protocol_id": protocol_id,
                "length_field": length_field,
                "unit_id": unit_id,
                "function_code": func_code,
                "function_name": self._modbus_function_name(func_code),
            })

            # Simple decoding for some common function codes
            if func_code in (3, 4, 5, 6, 15, 16, 8):
                details = self._decode_modbus_pdu(func_code, pdu)
                parsed.update(details)

            # Build human summary
            parsed["summary"] = self._build_modbus_summary(parsed)

            # Basic Modbus attack classification
            attack = self._classify_modbus_attack(ip, "modbus", parsed, now)

        except Exception as e:
            parsed["summary"] = f"Error parsing Modbus packet: {e!r}"

        return parsed, attack

    def _modbus_function_name(self, func_code: int) -> str:
        """
        Map Modbus function code to human-readable name.
        """
        names = {
            1: "Read Coils",
            2: "Read Discrete Inputs",
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            8: "Diagnostics",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers",
        }
        return names.get(func_code, "Unknown")

    def _decode_modbus_pdu(self, func_code: int, pdu: bytes) -> Dict[str, Any]:
        """
        Decode parts of the Modbus PDU for common function codes.
        """
        d: Dict[str, Any] = {}
        try:
            # pdu[0] is function code
            if len(pdu) < 3:
                return d
            if func_code in (3, 4):
                # Read registers: func, start_hi, start_lo, count_hi, count_lo
                if len(pdu) >= 5:
                    start_addr = int.from_bytes(pdu[1:3], "big")
                    count = int.from_bytes(pdu[3:5], "big")
                    d["start_address"] = start_addr
                    d["quantity"] = count
            elif func_code in (5, 6):
                # Write single: func, addr_hi, addr_lo, value_hi, value_lo
                if len(pdu) >= 5:
                    addr = int.from_bytes(pdu[1:3], "big")
                    value = int.from_bytes(pdu[3:5], "big")
                    d["address"] = addr
                    d["value"] = value
            elif func_code in (15, 16):
                # Write multiple: func, addr_hi, addr_lo, count_hi, count_lo, byte_count, ...
                if len(pdu) >= 6:
                    start_addr = int.from_bytes(pdu[1:3], "big")
                    count = int.from_bytes(pdu[3:5], "big")
                    byte_count = pdu[5]
                    d["start_address"] = start_addr
                    d["quantity"] = count
                    d["byte_count"] = byte_count
            elif func_code == 8:
                # Diagnostics: func, sub_hi, sub_lo, data_hi, data_lo
                if len(pdu) >= 3:
                    subfunc = int.from_bytes(pdu[1:3], "big")
                    d["subfunction"] = subfunc
        except Exception:
            # If anything goes wrong, just skip detailed decoding
            pass
        return d

    def _build_modbus_summary(self, parsed: Dict[str, Any]) -> str:
        """
        Build a human-readable Modbus summary line.
        """
        if not parsed.get("valid"):
            return parsed.get("summary", "Invalid Modbus packet")

        func_name = parsed.get("function_name", "Unknown")
        fc = parsed.get("function_code", -1)

        if fc in (3, 4):
            return (
                f"{func_name} from unit {parsed.get('unit_id')} "
                f"start={parsed.get('start_address')} qty={parsed.get('quantity')}"
            )
        if fc in (5, 6):
            return (
                f"{func_name} on unit {parsed.get('unit_id')} "
                f"addr={parsed.get('address')} value={parsed.get('value')}"
            )
        if fc in (15, 16):
            return (
                f"{func_name} on unit {parsed.get('unit_id')} "
                f"start={parsed.get('start_address')} qty={parsed.get('quantity')}"
            )
        if fc == 8:
            sub = parsed.get("subfunction")
            return f"Diagnostics subfunction={sub} from unit {parsed.get('unit_id')}"

        return f"Function {fc} ({func_name}) from unit {parsed.get('unit_id')}"

    def _classify_modbus_attack(
        self,
        ip: str,
        protocol: str,
        parsed: Dict[str, Any],
        now: datetime.datetime,
    ) -> Dict[str, Any]:
        """
        Very simple Modbus attack classification logic.
        """
        result: Dict[str, Any] = {
            "is_attack": False,
            "type": "none",
        }

        if not parsed.get("valid"):
            return result

        fc = parsed.get("function_code")
        attack_type = None

        # Rule 1: Diagnostics listen-only (DoS style)
        if fc == 8 and parsed.get("subfunction") == 4:
            attack_type = "modbus_listen_only_dos"

        # Rule 2: Large write of many registers could be "mass write"
        qty = parsed.get("quantity")
        if fc in (15, 16) and qty is not None and qty > 10:
            attack_type = "mass_write_many_registers"

        # Rule 3: Writes to very low or special addresses
        addr = parsed.get("address") or parsed.get("start_address")
        if fc in (5, 6, 15, 16) and addr is not None and addr < 10:
            attack_type = "write_to_critical_address"

        if attack_type:
            session_info = self._attack_tracker.update(ip, protocol, attack_type, now)
            result.update({
                "is_attack": True,
                "type": attack_type,
            })
            result.update(session_info)

        return result

    # ========================= DNP3 HANDLING =========================

    def _handle_dnp3_packet(
        self,
        data: bytes,
        ip: str,
        port: int,
        now: datetime.datetime,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Very lightweight DNP3 parser and attack classifier.
        This does not fully implement DNP3; it's enough for a demo.
        """
        parsed: Dict[str, Any] = {
            "valid": False,
            "summary": "DNP3 packet (lightly parsed)",
        }
        attack: Dict[str, Any] = {
            "is_attack": False,
            "type": "none",
        }

        try:
            if len(data) < 10:
                parsed["summary"] = "Too short to be valid DNP3."
                return parsed, attack

            # Assume standard 10-byte header and treat byte 10 as App Layer function code
            app_func_code = data[10] if len(data) > 10 else None
            parsed.update({
                "valid": True,
                "app_function_code": app_func_code,
                "app_function_name": self._dnp3_app_func_name(app_func_code) if app_func_code is not None else "Unknown",
            })

            parsed["summary"] = f"DNP3 app_fc={parsed['app_function_code']} ({parsed['app_function_name']})"

            # Simple DNP3 attack classifier
            attack = self._classify_dnp3_attack(ip, "dnp3", parsed, now)

        except Exception as e:
            parsed["summary"] = f"Error parsing DNP3 packet: {e!r}"

        return parsed, attack

    def _dnp3_app_func_name(self, fc: Optional[int]) -> str:
        """
        Map DNP3 Application Function Code to name.
        """
        if fc is None:
            return "Unknown"
        names = {
            0: "CONFIRM",
            1: "READ",
            2: "WRITE",
            3: "SELECT",
            4: "OPERATE",
            5: "DIRECT_OPERATE",
            6: "DIRECT_OPERATE_NO_ACK",
            7: "FREEZE",
            8: "FREEZE_NO_ACK",
            9: "COLD_RESTART",
            10: "WARM_RESTART",
        }
        return names.get(fc, "Unknown")

    def _classify_dnp3_attack(
        self,
        ip: str,
        protocol: str,
        parsed: Dict[str, Any],
        now: datetime.datetime,
    ) -> Dict[str, Any]:
        """
        Very small DNP3 attack classification.
        Treat control operations as suspicious/attack.
        """
        result: Dict[str, Any] = {
            "is_attack": False,
            "type": "none",
        }
        if not parsed.get("valid"):
            return result

        fname = parsed.get("app_function_name", "")
        attack_type = None

        # Treat direct control operations as suspicious/attack
        if fname in ("OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NO_ACK"):
            attack_type = "dnp3_control_operation"

        if attack_type:
            session_info = self._attack_tracker.update(ip, protocol, attack_type, now)
            result.update({
                "is_attack": True,
                "type": attack_type,
            })
            result.update(session_info)

        return result

    # ========================= LOGGING & SESSION HEADERS =========================

    def _write_session_header(self):
        """
        Writes a cyan-colored session header at the start of a server run.
        """
        start_str = self.session_start.strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            f"{CYAN}██████████████████████████████████████████████████",
            f" ICS MONITORING SERVER - SESSION START",
            f" Session ID: {self.session_id}",
            f" Start Time: {start_str}",
            f"██████████████████████████████████████████████████{RESET}\n",
        ]
        text = "\n".join(lines)
        with self._log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(text)

    def _write_session_footer(self):
        """
        Writes a cyan-colored session footer at the end of a server run.
        """
        end_time = datetime.datetime.utcnow()
        end_str = end_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            f"{CYAN}██████████████████████████████████████████████████",
            f" SESSION END",
            f" Session ID: {self.session_id}",
            f" End Time: {end_str}",
            f"██████████████████████████████████████████████████{RESET}\n",
        ]
        text = "\n".join(lines)
        with self._log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(text)

    def _log_event(self, event: Dict[str, Any]):
        """
        Writes a pretty, colorized log entry for a single event.
        """
        attack = event["attack"]

        # Severity logic
        if attack.get("is_attack"):
            duration = attack.get("session_duration_seconds", 0)
            if duration is not None and duration > 30:
                severity = "CRITICAL"
                color = BOLD + RED
            else:
                severity = "ATTACK"
                color = RED
        else:
            # Very simple heuristic for WARN: look for certain words
            if "write" in event["summary"].lower() and "critical" in event["summary"].lower():
                severity = "WARN"
                color = YELLOW
            else:
                severity = "INFO"
                color = GREEN

        # Build pretty log entry
        pretty_lines = []
        pretty_lines.append(color + "──────────────────────────────────────────────" + RESET)
        pretty_lines.append(f"{color}Severity: {severity}{RESET}")
        pretty_lines.append(f"Timestamp: {event['timestamp']}")
        pretty_lines.append(f"Client: {event['client']['ip']}:{event['client']['port']}")
        pretty_lines.append(f"Protocol: {event['protocol'].upper()}")
        pretty_lines.append("")
        pretty_lines.append("Summary:")
        pretty_lines.append(f"  {event['summary']}")

        # Parsed fields
        parsed = event["parsed"]
        if parsed.get("valid"):
            pretty_lines.append("")
            pretty_lines.append("Parsed Fields:")
            for k, v in parsed.items():
                if k in ("valid", "summary"):
                    continue
                pretty_lines.append(f"  {k.replace('_', ' ').title()}: {v}")

        # Attack classification
        pretty_lines.append("")
        pretty_lines.append("Attack Classification:")
        if attack.get("is_attack"):
            pretty_lines.append(f"  Status: {color}ATTACK DETECTED{RESET}")
            pretty_lines.append(f"  Type: {attack.get('type')}")
            pretty_lines.append(f"  Session ID: {attack.get('session_id')}")
            pretty_lines.append(f"  Duration: {attack.get('session_duration_seconds')} seconds")
        else:
            pretty_lines.append("  Status: Normal Traffic")

        # Raw info
        pretty_lines.append("")
        pretty_lines.append("Raw:")
        pretty_lines.append(f"  Length: {event['raw']['length']} bytes")
        pretty_lines.append(f"  Hex (first 32B): {event['raw']['hex_preview']}")
        pretty_lines.append(color + "──────────────────────────────────────────────" + RESET + "\n")

        pretty_text = "\n".join(pretty_lines)
        with self._log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(pretty_text)

        # Short CLI summary line (also colored)
        print(
            f"[{event['timestamp']}] {color}{severity}{RESET} "
            f"{event['protocol'].upper()} {event['client']['ip']}:{event['client']['port']} → {event['summary']}"
        )


def main():
    """
    Entry point: parses optional CLI args and starts the server.
    Usage:
        python3 ics_server.py
        python3 ics_server.py [modbus_port] [dnp3_port]
    """
    modbus_port = DEFAULT_MODBUS_PORT
    dnp3_port = DEFAULT_DNP3_PORT

    if len(sys.argv) > 1:
        try:
            modbus_port = int(sys.argv[1])
        except ValueError:
            print("Usage: python ics_server.py [modbus_port] [dnp3_port]")
            sys.exit(1)
    if len(sys.argv) > 2:
        try:
            dnp3_port = int(sys.argv[2])
        except ValueError:
            print("Usage: python ics_server.py [modbus_port] [dnp3_port]")
            sys.exit(1)

    server = ICSMonitoringServer(
        modbus_port=modbus_port,
        dnp3_port=dnp3_port,
    )
    server.start()


if __name__ == "__main__":
    main()
