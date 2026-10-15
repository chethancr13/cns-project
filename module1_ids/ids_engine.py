"""
Intrusion Detection System (IDS) - Core Engine
==============================================
A multi-threaded, hybrid host/network Intrusion Detection System in Python.

Detection Capabilities:
1. Port Scan Detection (Horizontal & Vertical scans via time-window connection tracking)
2. Signature & Heuristic Attack Detection (SQLi, Directory Traversal, Command Injection, XSS)
3. Connection Flooding / Rate Spike Detection (DoS heuristics)
4. Automated Alert Logging & Structured Event Reporting
"""

import time
import socket
import select
import threading
import re
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("IDS_ENGINE")


class AttackSignature:
    """Represents a rule for signature-based intrusion detection."""
    def __init__(self, name: str, pattern: str, severity: str, description: str):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.description = description

    def match(self, payload: str) -> bool:
        return bool(self.pattern.search(payload))


# Standard Attack Signatures
DEFAULT_SIGNATURES = [
    AttackSignature(
        name="Path_Traversal",
        pattern=r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
        severity="HIGH",
        description="Directory/Path traversal attempt targeting file system boundaries"
    ),
    AttackSignature(
        name="SQL_Injection",
        pattern=r"('|--|;|/\*|\*/|UNION\s+SELECT|OR\s+['\"0-9]+=['\"0-9]+|1=1)",
        severity="CRITICAL",
        description="SQL injection pattern attempting to manipulate database query logic"
    ),
    AttackSignature(
        name="Command_Injection",
        pattern=r"(;\s*(cat|ls|whoami|id|bash|sh|curl|wget)\b|\|\s*(bash|sh)|`.*`|\$\(.*\))",
        severity="CRITICAL",
        description="OS Command injection attempt targeting system execution"
    ),
    AttackSignature(
        name="Cross_Site_Scripting",
        pattern=r"(<script.*?>|javascript:|onload=|onerror=|alert\(|document\.cookie)",
        severity="MEDIUM",
        description="XSS payload attempting to execute malicious client-side script"
    ),
    AttackSignature(
        name="Nmap_UserAgent_Scan",
        pattern=r"(Nmap|Nikto|sqlmap|masscan|zgrab)",
        severity="HIGH",
        description="Automated security scanner or vulnerability scanner signature"
    ),
]


class Alert:
    """Represents an IDS security alert."""
    def __init__(self, alert_type: str, severity: str, src_ip: str, 
                 dst_port: int, details: str, payload_sample: str = ""):
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.alert_type = alert_type
        self.severity = severity
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.details = details
        self.payload_sample = payload_sample[:120] if payload_sample else ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_port": self.dst_port,
            "details": self.details,
            "payload_sample": self.payload_sample
        }

    def __str__(self) -> str:
        return (f"[{self.timestamp}] [{self.severity}] {self.alert_type} "
                f"from {self.src_ip} on port {self.dst_port}: {self.details}")


class IntrusionDetectionSystem:
    """
    Intrusion Detection System (IDS) Engine:
    - Listens on monitored trap & decoy ports
    - Tracks per-IP connection attempts using sliding-window metrics
    - Detects port scanning attacks (threshold of distinct ports in sliding time window)
    - Inspects incoming payloads against signature database
    - Generates real-time alerts and records to persistent log
    """
    def __init__(self,
                 host: str = "127.0.0.1",
                 monitored_ports: Optional[List[int]] = None,
                 scan_port_threshold: int = 3,
                 scan_window_seconds: float = 4.0,
                 burst_connection_threshold: int = 15,
                 log_file: str = "ids_alerts.log"):
        self.host = host
        # Default monitored decoy & service trap ports
        self.monitored_ports = monitored_ports or [2121, 2222, 2323, 8080, 8443, 9000]
        self.scan_port_threshold = scan_port_threshold
        self.scan_window_seconds = scan_window_seconds
        self.burst_connection_threshold = burst_connection_threshold
        self.log_file = log_file

        self.signatures = list(DEFAULT_SIGNATURES)
        self.alerts: List[Alert] = []
        self.alert_callbacks: List[Callable[[Alert], None]] = []

        # Sliding window trackers: {src_ip: deque([(timestamp, port), ...])}
        self.connection_history: Dict[str, deque] = defaultdict(deque)
        # Lock for thread safety
        self.lock = threading.Lock()

        self._server_sockets: List[socket.socket] = []
        self._running = False
        self._listen_thread: Optional[threading.Thread] = None

    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Register a callback for real-time notification on alerts."""
        self.alert_callbacks.append(callback)

    def trigger_alert(self, alert: Alert):
        """Record and dispatch an alert."""
        with self.lock:
            self.alerts.append(alert)

        # Write to log file
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to log file {self.log_file}: {e}")

        logger.warning(f"🚨 IDS ALERT: {alert}")

        # Notify callbacks
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def _record_connection(self, src_ip: str, port: int):
        """Track connection attempt and check for port scan or flood behavior."""
        now = time.time()
        with self.lock:
            history = self.connection_history[src_ip]
            history.append((now, port))

            # Evict entries outside time window
            cutoff = now - self.scan_window_seconds
            while history and history[0][0] < cutoff:
                history.popleft()

            # Analyze distinct ports targeted
            targeted_ports = {p for _, p in history}
            total_attempts = len(history)

        # Check for Port Scanning
        if len(targeted_ports) >= self.scan_port_threshold:
            alert = Alert(
                alert_type="PORT_SCAN_DETECTED",
                severity="HIGH",
                src_ip=src_ip,
                dst_port=port,
                details=f"Host scanned {len(targeted_ports)} unique ports ({sorted(list(targeted_ports))}) within {self.scan_window_seconds}s"
            )
            self.trigger_alert(alert)

        # Check for Connection Burst / Flood
        if total_attempts >= self.burst_connection_threshold:
            alert = Alert(
                alert_type="CONNECTION_FLOOD_DETECTED",
                severity="HIGH",
                src_ip=src_ip,
                dst_port=port,
                details=f"Host generated {total_attempts} connections within {self.scan_window_seconds}s (Rate anomaly)"
            )
            self.trigger_alert(alert)

    def _inspect_payload(self, src_ip: str, port: int, payload_bytes: bytes):
        """Deep packet payload inspection against intrusion signatures."""
        try:
            payload_text = payload_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return

        if not payload_text:
            return

        for sig in self.signatures:
            if sig.match(payload_text):
                alert = Alert(
                    alert_type=f"SIGNATURE_MATCH:{sig.name}",
                    severity=sig.severity,
                    src_ip=src_ip,
                    dst_port=port,
                    details=sig.description,
                    payload_sample=payload_text
                )
                self.trigger_alert(alert)

    def _handle_client(self, client_sock: socket.socket, src_addr: Tuple[str, int], server_port: int):
        """Handle incoming client connection, inspect payload, and close."""
        src_ip = src_addr[0]
        self._record_connection(src_ip, server_port)

        try:
            client_sock.settimeout(0.5)
            data = client_sock.recv(4096)
            if data:
                self._inspect_payload(src_ip, server_port, data)
                # Send polite decoy response
                client_sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nAccess Denied: Activity Monitored.\r\n")
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def start(self):
        """Start listening on all monitored ports."""
        self._running = True
        self._server_sockets = []

        for port in self.monitored_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, port))
                s.listen(50)
                s.setblocking(False)
                self._server_sockets.append(s)
                logger.info(f"IDS Sensor active on {self.host}:{port}")
            except Exception as e:
                logger.warning(f"Could not bind to port {port}: {e}")

        if not self._server_sockets:
            raise RuntimeError("IDS failed to bind to any monitored ports.")

        self._listen_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._listen_thread.start()
        logger.info("IDS Engine started successfully.")

    def _run_loop(self):
        """Non-blocking select loop across all monitored sockets."""
        socket_to_port = {s: s.getsockname()[1] for s in self._server_sockets}

        while self._running:
            try:
                readable, _, _ = select.select(self._server_sockets, [], [], 0.5)
                for s in readable:
                    try:
                        client_sock, src_addr = s.accept()
                        port = socket_to_port[s]
                        t = threading.Thread(
                            target=self._handle_client,
                            args=(client_sock, src_addr, port),
                            daemon=True
                        )
                        t.start()
                    except Exception:
                        pass
            except Exception:
                break

    def stop(self):
        """Stop IDS engine and close sockets."""
        self._running = False
        for s in self._server_sockets:
            try:
                s.close()
            except Exception:
                pass
        self._server_sockets = []
        if self._listen_thread:
            self._listen_thread.join(timeout=1.0)
        logger.info("IDS Engine stopped.")

    def get_summary(self) -> dict:
        """Return diagnostic metrics of detected intrusions."""
        with self.lock:
            alert_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            ip_counts = defaultdict(int)
            for a in self.alerts:
                alert_counts[a.alert_type] += 1
                severity_counts[a.severity] += 1
                ip_counts[a.src_ip] += 1

            return {
                "total_alerts": len(self.alerts),
                "by_type": dict(alert_counts),
                "by_severity": dict(severity_counts),
                "by_ip": dict(ip_counts),
            }


if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
    print("IDS running. Press Ctrl+C to terminate.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ids.stop()
