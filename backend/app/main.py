from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from cyber_hygiene_scanner.services.http_checks import HttpScanError
from cyber_hygiene_scanner.services.scanner import scan_target


class ScanRequest(BaseModel):
    target_url: str
    skip_ports: bool = False


app = FastAPI(
    title="Cyber Hygiene Scanner API",
    description="Web API for running basic and safe web security hygiene scans.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
def scan_website(payload: ScanRequest):
    try:
        return scan_target(
            payload.target_url,
            skip_ports=payload.skip_ports,
        )
    except (ValueError, HttpScanError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc