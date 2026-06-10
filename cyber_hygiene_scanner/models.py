from pydantic import BaseModel, Field
from typing import List, Optional


class HeaderCheck(BaseModel):
    name: str
    present: bool
    value: Optional[str] = None
    recommendation: str


class PortCheck(BaseModel):
    port: int
    service: str
    open: bool


class ScanSummary(BaseModel):
    target: str
    normalized_url: str
    score: int = Field(ge=0, le=100)
    risk_level: str
    https_enabled: bool
    redirects_to_https: bool
    server_header: Optional[str] = None
    powered_by_header: Optional[str] = None
    headers: List[HeaderCheck]
    ports: List[PortCheck]
    recommendations: List[str]
