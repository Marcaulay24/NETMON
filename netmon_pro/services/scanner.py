from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import socket
import subprocess
import platform
import re

# Optional scapy
try:
    from scapy.all import srp, Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class AsyncScannerService:
    """Non-blocking scan orchestration using asyncio + worker threads."""

    def __init__(self, max_workers: int = 64):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def trigger_scan(self, target: str | None = None) -> dict:
        target = target or "local_subnet"
        started = datetime.utcnow().isoformat()

        def blocking_scan() -> dict:
            hosts = []
            
            # 1. Try Scapy ARP scan for local network (most accurate and fastest)
            if SCAPY_AVAILABLE and target == "local_subnet":
                try:
                    # Get default gateway/prefix (simplistic for stub)
                    res = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=2)
                    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', res.stdout)
                    if match:
                        gw = match.group(1)
                        prefix = ".".join(gw.split(".")[:-1]) + ".0/24"
                        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=prefix), timeout=2, verbose=False)
                        for _, rcv in ans:
                            hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "status": "up"})
                        if hosts:
                            return {"target": prefix, "status": "completed", "hosts_found": len(hosts), "hosts": hosts}
                except: pass

            # 2. Threaded Ping Fallback
            def ping_host(ip):
                cmd = ['ping', '-n', '1', '-w', '500', ip] if platform.system() == 'Windows' else ['ping', '-c', '1', '-W', '1', ip]
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return ip if res.returncode == 0 else None

            # Assuming a /24 if local_subnet
            base_ip = "192.168.1." # Placeholder
            ips = [f"{base_ip}{i}" for i in range(1, 255)]
            
            with ThreadPoolExecutor(max_workers=50) as p_executor:
                results = list(p_executor.map(ping_host, ips))
                for ip in results:
                    if ip:
                        hosts.append({"ip": ip, "status": "up"})

            return {
                "target": target,
                "status": "completed",
                "hosts_found": len(hosts),
                "hosts": hosts,
                "note": "Parallel scan complete",
            }

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(self.executor, blocking_scan)
        result["started_at"] = started
        result["finished_at"] = datetime.utcnow().isoformat()
        return result
