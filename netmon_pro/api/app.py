from __future__ import annotations

from fastapi import FastAPI, Depends, Header, HTTPException

from netmon_pro.container import build_container

container = build_container()
app = FastAPI(title="NETMON PRO Local API", version="0.1.0")


def require_api_key(x_api_key: str = Header(default="")):
    if x_api_key != container.config.api.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/api/devices", dependencies=[Depends(require_api_key)])
async def list_devices():
    # Replace with ORM query layer
    return {"items": [], "count": 0}


@app.get("/api/alerts", dependencies=[Depends(require_api_key)])
async def list_alerts():
    return {"items": [], "count": 0}


@app.post("/api/scan/trigger", dependencies=[Depends(require_api_key)])
async def trigger_scan(target: str | None = None):
    return await container.scanner.trigger_scan(target)


@app.get("/api/compliance/score", dependencies=[Depends(require_api_key)])
async def compliance_score():
    return await container.compliance.compliance_score()


@app.get("/api/reports/generate", dependencies=[Depends(require_api_key)])
async def generate_report(report_type: str = "executive"):
    return {"status": "queued", "report_type": report_type}
