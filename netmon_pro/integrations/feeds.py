from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FeedConfig:
    abuseipdb_key: str = ""
    shodan_key: str = ""
    virustotal_key: str = ""
    otx_key: str = ""
