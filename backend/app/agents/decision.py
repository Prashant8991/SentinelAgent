import uuid
from typing import Dict, Any, List
from datetime import datetime

# Deterministic safety matrix for SOC actions
RISK_LEVEL_MAP = {
    "FLAG_BENIGN": "LOW",
    "CREATE_TICKET": "LOW",
    "APPLY_RATE_LIMIT": "LOW",
    "BLOCK_IP": "MEDIUM",
    "KILL_SESSION": "HIGH",
    "REVOKE_CREDENTIALS": "HIGH",
    "ISOLATE_HOST": "CRITICAL"
}

# Actions that MUST ALWAYS have human analyst confirmation
MANDATORY_HITL_ACTIONS = {"ISOLATE_HOST", "REVOKE_CREDENTIALS", "KILL_SESSION"}

def evaluate_guardrails(state: Dict[str, Any]) -> Dict[str, Any]:
    synthesis = state.get("synthesis", {})
    recommended_action = synthesis.get("recommended_action", "CREATE_TICKET")
    alert = state.get("alert", {})
    incident_id = state.get("incident_id", "")

    risk = RISK_LEVEL_MAP.get(recommended_action, "HIGH")
    requires_approval = (recommended_action in MANDATORY_HITL_ACTIONS) or (risk in ["HIGH", "CRITICAL"])

    target = alert.get("destination_ip") if recommended_action == "ISOLATE_HOST" else alert.get("source_ip", "0.0.0.0")

    justification = (
        f"Automated risk guardrail assessed action '{recommended_action}' as {risk} risk. "
        f"{'CRITICAL GUARDRAIL: Host isolation or credential disruption requires human sign-off.' if requires_approval else 'Safe idempotent action authorized for auto-remediation.'}"
    )

    action_record = {
        "id": f"act_{uuid.uuid4().hex[:8]}",
        "incident_id": incident_id,
        "action_type": recommended_action,
        "target": target,
        "risk_level": risk,
        "requires_approval": requires_approval,
        "status": "PENDING_APPROVAL" if requires_approval else "APPROVED",
        "justification": justification,
        "created_at": datetime.utcnow().isoformat(),
        "resolved_at": None,
        "resolved_by": None
    }

    return {
        "proposed_actions": [action_record],
        "hitl_required": requires_approval
    }
