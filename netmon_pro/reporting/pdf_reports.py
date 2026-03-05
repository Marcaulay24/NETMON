from __future__ import annotations

from datetime import datetime
from pathlib import Path


def generate_executive_text_report(path: str, analyst: str = "Analyst") -> str:
    p = Path(path)
    p.write_text(
        "\n".join(
            [
                "NETMON PRO Executive Report",
                f"Generated: {datetime.utcnow().isoformat()}",
                f"Analyst: {analyst}",
                "Summary: Modular reporting pipeline initialized.",
            ]
        ),
        encoding="utf-8",
    )
    return str(p)
