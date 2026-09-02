import hashlib
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, String, Integer, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./sentinel.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class IncidentRecord(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    alert_type = Column(String, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String)
    destination_port = Column(Integer)
    ml_severity = Column(String)
    final_severity = Column(String, index=True)
    status = Column(String, default="INVESTIGATED")
    root_cause = Column(Text)
    mitre_tactics = Column(Text)  # JSON serialized list
    investigation_steps = Column(Text)  # JSON serialized list
    remediation_actions = Column(Text)  # JSON serialized list
    timeline = Column(Text)  # JSON serialized list
    audit_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, index=True)
    actor = Column(String)  # "AGENT" or "HUMAN:analyst"
    action_type = Column(String)
    target = Column(String)
    details = Column(Text)
    sha256_hash = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class PatternMemoryRecord(Base):
    __tablename__ = "pattern_memory"

    signature_hash = Column(String, primary_key=True, index=True)
    alert_type = Column(String)
    signature_pattern = Column(String)
    resolved_severity = Column(String)
    typical_action = Column(String)
    root_cause_summary = Column(Text)
    occurrence_count = Column(Integer, default=1)
    last_seen = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def compute_audit_hash(data: Dict[str, Any]) -> str:
    raw_str = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

def save_incident(incident_data: Dict[str, Any]):
    db = SessionLocal()
    try:
        record = IncidentRecord(
            id=incident_data["id"],
            alert_type=incident_data["alert"]["alert_type"],
            source_ip=incident_data["alert"]["source_ip"],
            destination_ip=incident_data["alert"]["destination_ip"],
            destination_port=incident_data["alert"]["destination_port"],
            ml_severity=incident_data["ml_triage"]["ml_severity"],
            final_severity=incident_data["final_severity"],
            status=incident_data.get("status", "INVESTIGATED"),
            root_cause=incident_data.get("root_cause", ""),
            mitre_tactics=json.dumps(incident_data.get("mitre_tactics", [])),
            investigation_steps=json.dumps(incident_data.get("investigation_steps", []), default=str),
            remediation_actions=json.dumps(incident_data.get("remediation_actions", []), default=str),
            timeline=json.dumps(incident_data.get("timeline", [])),
            audit_hash=incident_data.get("audit_hash", "")
        )
        db.merge(record)
        db.commit()

        # Update pattern memory
        update_pattern_memory(db, incident_data)
    finally:
        db.close()

def update_pattern_memory(db, incident_data: Dict[str, Any]):
    alert = incident_data["alert"]
    sig_key = f"{alert.get('alert_type', '')}|{alert.get('signature', '')}|{alert.get('destination_port', '')}"
    sig_hash = hashlib.sha256(sig_key.encode("utf-8")).hexdigest()[:16]

    existing = db.query(PatternMemoryRecord).filter(PatternMemoryRecord.signature_hash == sig_hash).first()
    actions = incident_data.get("remediation_actions", [])
    typical_act = actions[0]["action_type"] if actions else "CREATE_TICKET"

    if existing:
        existing.occurrence_count += 1
        existing.last_seen = datetime.utcnow()
    else:
        new_pattern = PatternMemoryRecord(
            signature_hash=sig_hash,
            alert_type=alert.get("alert_type", "Unknown"),
            signature_pattern=alert.get("signature", ""),
            resolved_severity=incident_data.get("final_severity", "MEDIUM"),
            typical_action=typical_act,
            root_cause_summary=incident_data.get("root_cause", "")[:200],
            occurrence_count=1,
            last_seen=datetime.utcnow()
        )
        db.add(new_pattern)
    db.commit()

def log_audit_action(incident_id: str, actor: str, action_type: str, target: str, details: Dict[str, Any]) -> str:
    db = SessionLocal()
    try:
        details_str = json.dumps(details, sort_keys=True, default=str)
        hash_payload = f"{incident_id}:{actor}:{action_type}:{target}:{details_str}:{datetime.utcnow().isoformat()}"
        sha = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        rec = AuditLogRecord(
            incident_id=incident_id,
            actor=actor,
            action_type=action_type,
            target=target,
            details=details_str,
            sha256_hash=sha
        )
        db.add(rec)
        db.commit()
        return sha
    finally:
        db.close()

def query_historical_patterns(signature: str, alert_type: str) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        match = db.query(PatternMemoryRecord).filter(
            (PatternMemoryRecord.signature_pattern.ilike(f"%{signature}%")) |
            (PatternMemoryRecord.alert_type.ilike(f"%{alert_type}%"))
        ).order_by(PatternMemoryRecord.occurrence_count.desc()).first()
        if match:
            return {
                "signature_hash": match.signature_hash,
                "alert_type": match.alert_type,
                "resolved_severity": match.resolved_severity,
                "typical_action": match.typical_action,
                "root_cause_summary": match.root_cause_summary,
                "occurrences": match.occurrence_count,
                "last_seen": match.last_seen.isoformat()
            }
        return None
    finally:
        db.close()

def get_all_incidents() -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        records = db.query(IncidentRecord).order_by(IncidentRecord.created_at.desc()).limit(100).all()
        results = []
        for r in records:
            results.append({
                "id": r.id,
                "alert_type": r.alert_type,
                "source_ip": r.source_ip,
                "destination_ip": r.destination_ip,
                "destination_port": r.destination_port,
                "ml_severity": r.ml_severity,
                "final_severity": r.final_severity,
                "status": r.status,
                "root_cause": r.root_cause,
                "mitre_tactics": json.loads(r.mitre_tactics) if r.mitre_tactics else [],
                "investigation_steps": json.loads(r.investigation_steps) if r.investigation_steps else [],
                "remediation_actions": json.loads(r.remediation_actions) if r.remediation_actions else [],
                "timeline": json.loads(r.timeline) if r.timeline else [],
                "audit_hash": r.audit_hash,
                "created_at": r.created_at.isoformat()
            })
        return results
    finally:
        db.close()

def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        r = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not r:
            return None
        return {
            "id": r.id,
            "alert_type": r.alert_type,
            "source_ip": r.source_ip,
            "destination_ip": r.destination_ip,
            "destination_port": r.destination_port,
            "ml_severity": r.ml_severity,
            "final_severity": r.final_severity,
            "status": r.status,
            "root_cause": r.root_cause,
            "mitre_tactics": json.loads(r.mitre_tactics) if r.mitre_tactics else [],
            "investigation_steps": json.loads(r.investigation_steps) if r.investigation_steps else [],
            "remediation_actions": json.loads(r.remediation_actions) if r.remediation_actions else [],
            "timeline": json.loads(r.timeline) if r.timeline else [],
            "audit_hash": r.audit_hash,
            "created_at": r.created_at.isoformat()
        }
    finally:
        db.close()

def get_audit_logs() -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        records = db.query(AuditLogRecord).order_by(AuditLogRecord.timestamp.desc()).limit(100).all()
        return [{
            "id": r.id,
            "incident_id": r.incident_id,
            "actor": r.actor,
            "action_type": r.action_type,
            "target": r.target,
            "details": json.loads(r.details) if r.details else {},
            "sha256_hash": r.sha256_hash,
            "timestamp": r.timestamp.isoformat()
        } for r in records]
    finally:
        db.close()
