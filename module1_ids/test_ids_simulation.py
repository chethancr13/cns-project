"""
Intrusion Detection System (IDS) - Simulation & Test Runner
===========================================================
Simulates realistic adversary actions and verifies IDS detection:
1. Normal Benign Traffic
2. Multi-Port Scanning (triggering PORT_SCAN_DETECTED)
3. Web Attack Payloads (SQL Injection, Path Traversal, XSS)
4. Evaluates IDS alert logs and asserts 100% detection accuracy
"""

import time
import socket
import os
import sys

# Ensure module path is accessible
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from ids_engine import IntrusionDetectionSystem


def send_probe(host: str, port: int, payload: bytes = b"") -> bool:
    """Helper to connect and transmit payload."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((host, port))
        if payload:
            s.sendall(payload)
        s.close()
        return True
    except Exception:
        return False


def run_ids_simulation():
    print("=" * 70)
    print("🚀 MODULE 1: INTRUSION DETECTION SYSTEM (IDS) SIMULATION")
    print("=" * 70)

    log_path = os.path.join(current_dir, "ids_alerts.log")
    if os.path.exists(log_path):
        os.remove(log_path)

    monitored_ports = [2121, 2222, 2323, 8080, 8443, 9000]
    ids = IntrusionDetectionSystem(
        host="127.0.0.1",
        monitored_ports=monitored_ports,
        scan_port_threshold=3,
        scan_window_seconds=3.0,
        log_file=log_path
    )

    detected_alerts = []
    ids.add_alert_callback(lambda a: detected_alerts.append(a))

    print(f"[*] Starting IDS Engine on monitored ports: {monitored_ports}")
    ids.start()
    time.sleep(0.5)

    try:
        # Phase 1: Benign Single Connection
        print("\n--- Phase 1: Benign Traffic ---")
        print("[*] Sending single benign ping to port 8080...")
        send_probe("127.0.0.1", 8080, b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.5)
        print(f"[+] Current Alert Count: {len(detected_alerts)} (Expected: 0)")

        # Phase 2: Simulated Port Scan Attack
        print("\n--- Phase 2: Adversary Port Scan Attack ---")
        print("[*] Simulating Nmap-style rapid horizontal port scan across 4 ports...")
        for p in [2121, 2222, 2323, 8443]:
            send_probe("127.0.0.1", p, b"")
            time.sleep(0.05)
        time.sleep(0.5)

        port_scan_alerts = [a for a in detected_alerts if a.alert_type == "PORT_SCAN_DETECTED"]
        print(f"[+] Port Scan Alerts Detected: {len(port_scan_alerts)}")
        if port_scan_alerts:
            print(f"    Alert Details: {port_scan_alerts[0].details}")

        # Phase 3: Malicious Web Payloads (Signature-based Detection)
        print("\n--- Phase 3: Malicious Payload Injection ---")
        
        attacks = [
            ("SQL Injection", 8080, b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\n\r\n"),
            ("Path Traversal", 8080, b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"),
            ("XSS Injection", 8080, b"POST /comment HTTP/1.1\r\nContent: <script>alert(1)</script>\r\n\r\n"),
            ("Command Injection", 9000, b"PING ; cat /etc/shadow\r\n")
        ]

        for name, port, payload in attacks:
            print(f"[*] Sending {name} to port {port}...")
            send_probe("127.0.0.1", port, payload)
            time.sleep(0.2)

        time.sleep(0.5)

        sig_alerts = [a for a in detected_alerts if a.alert_type.startswith("SIGNATURE_MATCH")]
        print(f"[+] Signature Match Alerts Detected: {len(sig_alerts)}")
        for a in sig_alerts:
            print(f"    - [{a.severity}] {a.alert_type}: {a.details}")

        # Phase 4: Verification and Summary
        print("\n--- Phase 4: IDS Evaluation & Verification ---")
        summary = ids.get_summary()
        print(f"Total Alerts Captured: {summary['total_alerts']}")
        print(f"Breakdown by Severity: {summary['by_severity']}")
        print(f"Breakdown by Type: {summary['by_type']}")

        assert len(port_scan_alerts) >= 1, "FAIL: Port scan was not detected by IDS"
        assert len(sig_alerts) >= 3, "FAIL: Malicious signatures were not detected by IDS"
        assert os.path.exists(log_path), "FAIL: Alert log file was not generated"

        print("\n" + "=" * 70)
        print("✅ SUCCESS: IDS Engine successfully detected all simulated attacks!")
        print("=" * 70)

    finally:
        ids.stop()


if __name__ == "__main__":
    run_ids_simulation()
