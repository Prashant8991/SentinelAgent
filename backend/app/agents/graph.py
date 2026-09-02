import re
import uuid
from datetime import datetime
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from app.agents.state import AgentState
from app.ml.classifier import predict_alert_severity
from app.tools.threat_intel import (
    lookup_ip_reputation,
    lookup_cve,
    lookup_whois,
    lookup_file_hash,
    correlate_incident_memory
)
from app.llm.engine import llm_engine
from app.agents.decision import evaluate_guardrails
from app.agents.remediation import execute_remediation
from app.db.database import save_incident, compute_audit_hash

# --- Node 1: Ingestion ---
async def ingest_node(state: AgentState) -> Dict[str, Any]:
    alert = state["alert"]
    incident_id = state.get("incident_id") or f"inc_{uuid.uuid4().hex[:10]}"
    now = datetime.utcnow().isoformat()

    timeline = [f"[{now}] Alert {alert.get('id')} ingested: {alert.get('alert_type')} ({alert.get('signature')})"]
    trace = [{
        "node": "Ingestion Agent",
        "status": "COMPLETED",
        "thought": f"Ingested raw security telemetry. Normalized attributes: {alert.get('source_ip')} -> {alert.get('destination_ip')}:{alert.get('destination_port')} via {alert.get('protocol')}.",
        "timestamp": now
    }]

    return {
        "incident_id": incident_id,
        "current_node": "Ingestion Agent",
        "timeline": timeline,
        "trace_events": trace,
        "status": "INGESTED"
    }

# --- Node 2: Triage (Hybrid ML + LLM) ---
async def triage_node(state: AgentState) -> Dict[str, Any]:
    alert = state["alert"]
    now = datetime.utcnow().isoformat()

    ml_result = predict_alert_severity(alert)

    timeline_entry = f"[{now}] Pre-triage completed by Random Forest Classifier: {ml_result['ml_severity']} (Confidence: {ml_result['ml_confidence']*100:.1f}%)"
    trace_entry = {
        "node": "Triage Agent (ML)",
        "status": "COMPLETED",
        "thought": ml_result["initial_reasoning"],
        "telemetry": ml_result["features_used"],
        "timestamp": now
    }

    return {
        "ml_triage": ml_result,
        "current_node": "Triage Agent",
        "timeline": state["timeline"] + [timeline_entry],
        "trace_events": state["trace_events"] + [trace_entry],
        "status": "TRIAGED"
    }

# --- Node 3: Investigation (Tool Calling Loop) ---
async def investigate_node(state: AgentState) -> Dict[str, Any]:
    alert = state["alert"]
    ml_triage = state["ml_triage"]
    now = datetime.utcnow().isoformat()

    # Step 1: Formulate tool plan
    plan = await llm_engine.generate_investigation_plan(alert, ml_triage)
    tool_results = {}
    steps = []

    step_idx = 1
    # Execute tools autonomously
    for tool in plan:
        tool_start = datetime.utcnow().isoformat()
        res = {}
        thought_msg = ""

        if tool == "query_memory":
            thought_msg = "Checking SQLite pattern memory for repeat occurrences of this attack signature..."
            res = correlate_incident_memory(alert.get("signature", ""), alert.get("alert_type", ""))
            conclusion = f"Memory search: {'Matched existing pattern: ' + str(res.get('pattern_found', {}).get('typical_action')) if res.get('has_match') else 'No identical historical pattern found.'}"

        elif tool == "lookup_ip":
            src_ip = alert.get("source_ip", "")
            thought_msg = f"Querying IP reputation telemetry for ingress source: {src_ip}..."
            res = lookup_ip_reputation(src_ip)
            conclusion = f"Reputation Score: {res.get('abuse_confidence_score')}/100. ISP: {res.get('isp')}. Country: {res.get('country')}."

        elif tool == "lookup_cve":
            # Extract CVE if in signature or payload
            text = f"{alert.get('signature', '')} {alert.get('payload_sample', '')}"
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
            cve_id = cve_match.group(0).upper() if cve_match else "CVE-2021-44228"
            thought_msg = f"Investigating CVE vulnerability details for identifier: {cve_id}..."
            res = lookup_cve(cve_id)
            conclusion = f"CVSS Score: {res.get('cvss_score')}/10 ({res.get('severity')}). Vector: {res.get('vector')}."

        elif tool == "lookup_whois":
            src_ip = alert.get("source_ip", "")
            thought_msg = f"Performing WHOIS/RDAP registration lookup on {src_ip}..."
            res = lookup_whois(src_ip)
            conclusion = f"Registration info retrieved from {res.get('source')}."

        elif tool == "lookup_hash":
            payload = alert.get("payload_sample", "")
            thought_msg = "Analyzing payload cryptographic hash across antivirus telemetry engines..."
            res = lookup_file_hash(payload)
            conclusion = f"Detections: {res.get('malicious_detections')}/{res.get('total_scanners')} engines. Verdict: {res.get('verdict')}."

        tool_results[tool] = res
        steps.append({
            "step_number": step_idx,
            "thought": thought_msg,
            "tool_call": {
                "tool_name": tool,
                "query": alert.get("source_ip") if "ip" in tool else alert.get("signature", ""),
                "output": res,
                "latency_ms": res.get("latency_ms", 5.0),
                "timestamp": tool_start
            },
            "conclusion": conclusion
        })
        step_idx += 1

    # Step 2: Synthesize evidence
    synthesis = await llm_engine.generate_incident_synthesis(alert, ml_triage, tool_results)

    timeline_entry = f"[{now}] Autonomous investigation completed: Queried {len(plan)} tools. Final severity: {synthesis['final_severity']}."
    trace_entry = {
        "node": "Investigation Agent",
        "status": "COMPLETED",
        "thought": f"Completed multi-tool evidence collection. Root Cause: {synthesis['root_cause']}",
        "tools_executed": plan,
        "timestamp": now
    }

    return {
        "investigation_plan": plan,
        "tool_results": tool_results,
        "investigation_steps": steps,
        "synthesis": synthesis,
        "current_node": "Investigation Agent",
        "timeline": state["timeline"] + [timeline_entry],
        "trace_events": state["trace_events"] + [trace_entry],
        "status": "INVESTIGATED"
    }

# --- Node 4: Decision & Guardrails ---
async def decision_node(state: AgentState) -> Dict[str, Any]:
    guardrail_out = evaluate_guardrails(state)
    now = datetime.utcnow().isoformat()

    hitl = guardrail_out["hitl_required"]
    prop_action = guardrail_out["proposed_actions"][0]

    timeline_msg = f"[{now}] Decision Guardrails: Action '{prop_action['action_type']}' ({prop_action['risk_level']} risk). {'ESCALATED TO HUMAN ANALYST' if hitl else 'AUTHORIZED FOR AUTO-REMEDIATION'}."
    trace_entry = {
        "node": "Decision & Safety Guardrails",
        "status": "PENDING_APPROVAL" if hitl else "APPROVED",
        "thought": prop_action["justification"],
        "action": prop_action,
        "timestamp": now
    }

    return {
        "proposed_actions": guardrail_out["proposed_actions"],
        "hitl_required": hitl,
        "current_node": "Decision Guardrails",
        "timeline": state["timeline"] + [timeline_msg],
        "trace_events": state["trace_events"] + [trace_entry],
        "status": "PENDING_APPROVAL" if hitl else "AUTO_REMEDIATING"
    }

# --- Node 5: Remediation Executor ---
async def remediation_node(state: AgentState) -> Dict[str, Any]:
    proposed = state.get("proposed_actions", [])
    executed = []
    now = datetime.utcnow().isoformat()

    for act in proposed:
        if act.get("status") == "APPROVED" or not act.get("requires_approval"):
            res_act = execute_remediation(act, actor="AGENT")
            executed.append(res_act)

    timeline_msg = f"[{now}] Remediation Agent: Automatically executed {len(executed)} safe action(s)."
    trace_entry = {
        "node": "Response & Remediation Agent",
        "status": "COMPLETED",
        "thought": f"Executed pre-approved containment: {executed[0]['action_type'] if executed else 'None'}",
        "executed": executed,
        "timestamp": now
    }

    return {
        "executed_actions": executed,
        "current_node": "Remediation Agent",
        "timeline": state["timeline"] + [timeline_msg],
        "trace_events": state["trace_events"] + [trace_entry],
        "status": "REMEDIATED"
    }

# --- Node 6: Incident Reporting & Persistence ---
async def report_node(state: AgentState) -> Dict[str, Any]:
    now = datetime.utcnow().isoformat()
    synthesis = state.get("synthesis", {})
    alert = state.get("alert", {})
    ml_triage = state.get("ml_triage", {})

    status = "ESCALATED_TO_HUMAN" if state.get("hitl_required") else "REMEDIATED"

    # Compute tamper-evident non-repudiation audit hash
    audit_data = {
        "incident_id": state["incident_id"],
        "alert": alert,
        "synthesis": synthesis,
        "actions": state.get("executed_actions") or state.get("proposed_actions"),
        "timestamp": now
    }
    audit_hash = compute_audit_hash(audit_data)

    timeline_msg = f"[{now}] Final SOC Incident Report archived with SHA-256 audit hash: {audit_hash[:16]}..."
    trace_entry = {
        "node": "Reporting & Audit Agent",
        "status": "CLOSED",
        "thought": f"Archived incident record to SQLite memory. Status: {status}. Non-repudiation hash: {audit_hash}",
        "timestamp": now
    }

    final_state_data = {
        "id": state["incident_id"],
        "alert": alert,
        "ml_triage": ml_triage,
        "final_severity": synthesis.get("final_severity", "MEDIUM"),
        "status": status,
        "root_cause": synthesis.get("root_cause", ""),
        "mitre_tactics": synthesis.get("mitre_tactics", []),
        "investigation_steps": state.get("investigation_steps", []),
        "remediation_actions": state.get("executed_actions") or state.get("proposed_actions", []),
        "timeline": state["timeline"] + [timeline_msg],
        "audit_hash": audit_hash
    }

    # Save to SQLite Database
    save_incident(final_state_data)

    return {
        "status": status,
        "audit_hash": audit_hash,
        "timeline": state["timeline"] + [timeline_msg],
        "trace_events": state["trace_events"] + [trace_entry],
        "current_node": "Report Agent"
    }

# --- Conditional Edge Router ---
def route_after_decision(state: AgentState) -> str:
    if state.get("hitl_required", False):
        # High-risk action: halt automatic execution, skip to report for human queue
        return "report"
    return "remediate"

# --- Construct LangGraph Pipeline ---
def build_soc_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("ingest", ingest_node)
    workflow.add_node("triage", triage_node)
    workflow.add_node("investigate", investigate_node)
    workflow.add_node("decision", decision_node)
    workflow.add_node("remediate", remediation_node)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("ingest")
    workflow.add_edge("ingest", "triage")
    workflow.add_edge("triage", "investigate")
    workflow.add_edge("investigate", "decision")

    workflow.add_conditional_edges(
        "decision",
        route_after_decision,
        {
            "report": "report",
            "remediate": "remediate"
        }
    )

    workflow.add_edge("remediate", "report")
    workflow.add_edge("report", END)

    return workflow.compile()

soc_agent_graph = build_soc_graph()
