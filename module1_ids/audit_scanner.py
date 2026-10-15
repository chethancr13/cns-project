"""
Vulnerability & Security Audit Scanner
======================================
Performs defensive network reconnaissance and security assessment:
1. TCP Port Discovery (multi-threaded socket scanner)
2. Banner Grabbing & Service Version Detection
3. Basic Vulnerability & Security Posture Assessment (plaintext protocols, sensitive endpoints)
4. Optional Nmap integration (via python-nmap) when the Nmap binary is available
"""

import socket
import concurrent.futures
import shutil
import json
from typing import Dict, List, Any, Optional

try:
    import nmap
    HAS_PYTHON_NMAP = True
except ImportError:
    HAS_PYTHON_NMAP = False


COMMON_SERVICES = {
    21: "FTP (Plaintext File Transfer - Insecure)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Access - Insecure)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Service - Unencrypted)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (Encrypted Web Service)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Store",
    8080: "HTTP-Proxy / Alternative Web Server",
    8443: "HTTPS-Alt / Management Interface",
    9000: "SonarQube / FastCGI / Dev Server",
}

# Known security risk signatures for banner analysis
BANNER_VULNERABILITIES = [
    ("vsftpd 2.3.4", "CRITICAL", "CVE-2011-2523: Known backdoor command execution"),
    ("OpenSSH_7.2p2", "HIGH", "CVE-2016-6210: User enumeration vulnerability"),
    ("Apache/2.4.49", "CRITICAL", "CVE-2021-41773: Path Traversal & Remote Code Execution"),
    ("ProFTPD 1.3.5", "HIGH", "CVE-2015-3306: mod_copy unauthenticated arbitrary file copy"),
    ("telnet", "HIGH", "Insecure Protocol: Cleartext authentication transmitted"),
]


class VulnerabilityScanner:
    """Defensive port scanner and vulnerability posture assessment."""
    def __init__(self, target_host: str = "127.0.0.1", timeout: float = 1.0):
        self.target_host = target_host
        self.timeout = timeout
        self.has_nmap_binary = shutil.which("nmap") is not None and HAS_PYTHON_NMAP

    def probe_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Attempt TCP connection and grab service banner."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target_host, port))
            if result == 0:
                # Port is open, attempt banner grab
                banner = ""
                try:
                    s.settimeout(0.6)
                    # Trigger probe for HTTP or generic services
                    if port in (80, 8080, 8443):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        s.sendall(b"\r\n")
                    data = s.recv(1024)
                    banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass

                service_desc = COMMON_SERVICES.get(port, "Unknown / Custom Service")
                
                # Check for vulnerabilities in banner or service
                vulnerabilities = []
                for sig, sev, desc in BANNER_VULNERABILITIES:
                    if sig.lower() in banner.lower():
                        vulnerabilities.append({
                            "signature": sig,
                            "severity": sev,
                            "description": desc
                        })

                # Check for inherently insecure services
                if port in (21, 23):
                    vulnerabilities.append({
                        "signature": f"Port {port}",
                        "severity": "HIGH",
                        "description": "Cleartext transmission of credentials (lack of TLS/SSH encapsulation)"
                    })

                s.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service_desc,
                    "banner": banner[:100] if banner else "No banner returned",
                    "vulnerabilities": vulnerabilities
                }
            s.close()
        except Exception:
            pass
        return None

    def scan_ports(self, ports: List[int], max_workers: int = 20) -> List[Dict[str, Any]]:
        """Multi-threaded TCP port scan."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.probe_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    results.append(res)
        results.sort(key=lambda x: x["port"])
        return results

    def run_nmap_scan(self, ports_str: str = "21,22,80,443,8080") -> Optional[dict]:
        """Run scan using python-nmap if system binary is available."""
        if not self.has_nmap_binary:
            return None
        try:
            nm = nmap.PortScanner()
            scan_data = nm.scan(self.target_host, ports_str, arguments="-sV -T4")
            return scan_data
        except Exception as e:
            return {"error": str(e)}

    def audit_report(self, ports: List[int]) -> dict:
        """Generate comprehensive audit report."""
        scan_results = self.scan_ports(ports)
        total_open = len(scan_results)
        vuln_count = sum(len(r["vulnerabilities"]) for r in scan_results)

        return {
            "target": self.target_host,
            "total_ports_scanned": len(ports),
            "open_ports_count": total_open,
            "vulnerabilities_detected": vuln_count,
            "findings": scan_results,
            "engine": "python-nmap" if self.has_nmap_binary else "native-python-socket"
        }


if __name__ == "__main__":
    target = "127.0.0.1"
    ports_to_test = [21, 22, 23, 80, 443, 2121, 2222, 2323, 8080, 8443, 9000]
    print(f"[*] Starting Security Audit & Port Scan on {target}...")
    scanner = VulnerabilityScanner(target)
    report = scanner.audit_report(ports_to_test)
    print(json.dumps(report, indent=2))
