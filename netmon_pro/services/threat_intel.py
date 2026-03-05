from __future__ import annotations

from datetime import datetime


class ThreatIntelServiceImpl:
    def __init__(self):
        self.last_sync = None

    async def sync_feeds(self) -> dict:
        self.last_sync = datetime.utcnow().isoformat()
        return {
            "status": "ok",
            "last_sync": self.last_sync,
            "feeds": ["AbuseIPDB", "Shodan", "VirusTotal", "OTX"],
            "note": "feed connectors are module stubs; add API keys in config",
        }
