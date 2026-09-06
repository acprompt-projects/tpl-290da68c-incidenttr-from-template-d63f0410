from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import hashlib
import re

app = FastAPI(title="Incident Triage Service", version="1.0.0")

# --- In-memory store ---
incidents_db: dict[str, "Incident"] = {}
dedup_cache: dict[str, str] = {}

# --- Enums ---
class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class Status(str, Enum):
    open = "open"
    triaging = "triaging"
    acknowledged = "acknowledged"
    resolved = "resolved"
    suppressed = "suppressed"

class Source(str, Enum):
    prometheus = "prometheus"
    cloudwatch = "cloudwatch"
    datadog = "datadog"
    custom = "custom"

# --- Pydantic Models ---
class AlertPayload(BaseModel):
    alert_name: str = Field(..., min_length=1, max_length=256)
    source: Source
    labels: dict[str, str] = Field(default_factory=dict)
    description: str = Field(default="", max_length=2048)
    raw_payload: Optional[dict] = None

class IncidentCreate(AlertPayload):
    dedup_key: Optional[str] = None

class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[Status] = None
    assignee: Optional[str] = Field(None, max_length=128)
    notes: Optional[str] = Field(None, max_length=2048)

class IncidentOut(BaseModel):
    id: str
    alert_name: str
    source: Source
    labels: dict[str, str]
    description: str
    severity: Severity
    status: Status
    assignee: Optional[str]
    notes: Optional[str]
    dedup_key: str
    created_at: datetime
    updated_at: datetime

class ErrorResponse(BaseModel):
    detail: str

# --- Classification logic ---
_KEYWORD_SEVERITY: dict[Severity, list[str]] = {
    Severity.critical: ["out_of_memory", "disk_full", "data_loss", "security_breach", "prod_down"],
    Severity.high: ["high_latency", "error_rate", "cpu_spike", "connection_leak"],
    Severity.medium: ["warning", "degraded", "retry", "slow_query"],
    Severity.low: ["info", "heartbeat_miss", "debug"],
}

def classify_severity(alert_name: str, labels: dict[str, str]) -> Severity:
    text = (alert_name + " " + " ".join(labels.values())).lower()
    for sev, keywords in _KEYWORD_SEVERITY.items():
        if any(kw in text for kw in keywords):
            return sev
    if "env" in labels and labels["env"] == "production":
        return Severity.high
    return Severity.medium

def make_dedup_key(alert_name: str, source: Source, labels: dict[str, str]) -> str:
    canonical = f"{source.value}:{alert_name}:" + ",".join(
        f"{k}={v}" for k, v in sorted(labels.items())
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]

# --- Endpoints ---
@app.post("/incidents", response_model=IncidentOut, status_code=201,
           responses={409: {"model": ErrorResponse}})
def create_incident(payload: IncidentCreate):
    dedup = payload.dedup_key or make_dedup_key(payload.alert_name, payload.source, payload.labels)

    if dedup in dedup_cache:
        existing_id = dedup_cache[dedup]
        raise HTTPException(status_code=409, detail=f"Duplicate incident: {existing_id}")

    now = datetime.now(timezone.utc)
    inc_id = f"INC-{now.strftime('%Y%m%d')}-{len(incidents_db)+1:04d}"
    severity = classify_severity(payload.alert_name, payload.labels)

    incident = IncidentOut(
        id=inc_id,
        alert_name=payload.alert_name,
        source=payload.source,
        labels=payload.labels,
        description=payload.description,
        severity=severity,
        status=Status.open,
        assignee=None,
        notes=None,
        dedup_key=dedup,
        created_at=now,
        updated_at=now,
    )
    incidents_db[inc_id] = incident
    dedup_cache[dedup] = inc_id
    return incident

@app.get("/incidents/{incident_id}", response_model=IncidentOut,
         responses={404: {"model": ErrorResponse}})
def get_incident(incident_id: str):
    if incident_id not in incidents_db:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incidents_db[incident_id]

@app.patch("/incidents/{incident_id}/triage", response_model=IncidentOut,
           responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}})
def update_triage(incident_id: str, update: TriageUpdate):
    if incident_id not in incidents_db:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    incident = incidents_db[incident_id]

    if incident.status == Status.resolved and update.status not in (None, Status.resolved):
        raise HTTPException(status_code=422, detail="Cannot change status of a resolved incident")

    if update.severity is not None:
        incident.severity = update.severity
    if update.status is not None:
        incident.status = update.status
    if update.assignee is not None:
        incident.assignee = update.assignee
    if update.notes is not None:
        incident.notes = update.notes

    incident.updated_at = datetime.now(timezone.utc)
    incidents_db[incident_id] = incident
    return incident

@app.get("/health")
def health():
    return {"status": "healthy", "incidents_count": len(incidents_db)}