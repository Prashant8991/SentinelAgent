from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    KILL_SESSION = "KILL_SESSION"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    CREATE_TICKET = "CREATE_TICKET"
    FLAG_BENIGN = "FLAG_BENIGN"
    APPLY_RATE_LIMIT = "APPLY_RATE_LIMIT"

class ActionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    AUTO_EXECUTED = "AUTO_EXECUTED"

class SecurityAlert(BaseModel):
    id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str = "TCP"
    alert_type: str  # e.g., Brute Force, SQL Injection, Port Scan, Log4j Exploit, C2 Beacon
    signature: str
    payload_sample: Optional[str] = None
    packet_count: int = 1
    failed_attempts: int = 0
    raw_log: Optional[str] = None

class TriageResult(BaseModel):
    ml_severity: SeverityLevel
    ml_confidence: float
    features_used: Dict[str, Any]
    initial_reasoning: str

class ToolCallRecord(BaseModel):
    tool_name: str
    query: str
    output: Dict[str, Any]
    latency_ms: float
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class InvestigationStep(BaseModel):
    step_number: int
    thought: str
    tool_call: Optional[ToolCallRecord] = None
    conclusion: str

class HITLAction(BaseModel):
    id: str
    incident_id: str
    action_type: ActionType
    target: str
    risk_level: SeverityLevel
    requires_approval: bool
    status: ActionStatus
    justification: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None

class IncidentReport(BaseModel):
    id: str
    alert: SecurityAlert
    ml_triage: TriageResult
    investigation_steps: List[InvestigationStep] = []
    mitre_tactics: List[str] = []
    root_cause: str
    final_severity: SeverityLevel
    remediation_actions: List[HITLAction] = []
    timeline: List[str] = []
    status: str = "INVESTIGATED"  # INVESTIGATED, REMEDIATED, ESCALATED, CLOSED
    audit_hash: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class EvaluationMetric(BaseModel):
    incident_id: str
    scenario_name: str
    ground_truth_severity: SeverityLevel
    predicted_severity: SeverityLevel
    ground_truth_action: ActionType
    predicted_action: ActionType
    tools_called: List[str]
    latency_seconds: float
    severity_match: bool
    action_match: bool
    false_escalation: bool
