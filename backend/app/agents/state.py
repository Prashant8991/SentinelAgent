from typing import Dict, Any, List, Optional
from typing_extensions import TypedDict

class AgentState(TypedDict):
    incident_id: str
    alert: Dict[str, Any]
    ml_triage: Dict[str, Any]
    investigation_plan: List[str]
    tool_results: Dict[str, Any]
    investigation_steps: List[Dict[str, Any]]
    synthesis: Dict[str, Any]
    proposed_actions: List[Dict[str, Any]]
    executed_actions: List[Dict[str, Any]]
    hitl_required: bool
    status: str
    timeline: List[str]
    audit_hash: str
    current_node: str
    trace_events: List[Dict[str, Any]]
