
import socket
import time

MODBUS_PORT = 1502
DNP3_PORT = 20000
IP = "127.0.0.1"

def send_packet(ip, port, packet_hex):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(bytes.fromhex(packet_hex))
        s.close()
    except Exception as e:
        print(f"[ERROR] {e}")

def test_modbus_read():
    print("[TEST] Modbus normal read")
    pkt = "000100000006010300000001"
    send_packet(IP, MODBUS_PORT, pkt)

def test_modbus_attack():
    print("[TEST] Modbus listen-only attack")
    pkt = "0001000000060108040000"
    send_packet(IP, MODBUS_PORT, pkt)

def test_modbus_critical_write():
    print("[TEST] Modbus critical write")
    pkt = "000100000006010600010005"
    send_packet(IP, MODBUS_PORT, pkt)

def test_dnp3_operate():
    print("[TEST] DNP3 OPERATE function")
    fake_header = "aa"*10
    app_fc = "04"
    tail = "0000"
    pkt = fake_header + app_fc + tail
    send_packet(IP, DNP3_PORT, pkt)

def run_all():
    print("\n===== ICS Server Test Suite =====\n")
    time.sleep(1)

    test_modbus_read()
    time.sleep(1)

    test_modbus_attack()
    time.sleep(1)

    test_modbus_critical_write()
    time.sleep(1)

    test_dnp3_operate()
    time.sleep(1)

    print("\nAll tests sent. Check server_report.log.\n")

if __name__ == "__main__":
    run_all()
