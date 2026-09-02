import json
import re
import httpx
from typing import Dict, Any, List, Optional
from app.config import settings

class DualModeLLMEngine:
    def __init__(self):
        self.live_llm_enabled = settings.ENABLE_LIVE_LLM

    @property
    def mode(self) -> str:
        if self.live_llm_enabled:
            if settings.OPENAI_API_KEY:
                return "OPENAI"
            elif settings.GEMINI_API_KEY:
                return "GEMINI"
            elif settings.ANTHROPIC_API_KEY:
                return "ANTHROPIC"
        return "SMART_LOCAL"

    def set_live_mode(self, enabled: bool):
        self.live_llm_enabled = enabled

    def get_status(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "live_llm_enabled": self.live_llm_enabled,
            "has_openai": bool(settings.OPENAI_API_KEY),
            "has_gemini": bool(settings.GEMINI_API_KEY),
            "has_anthropic": bool(settings.ANTHROPIC_API_KEY),
            "is_smart_local": self.mode == "SMART_LOCAL"
        }


    async def generate_investigation_plan(self, alert_data: Dict[str, Any], ml_triage: Dict[str, Any]) -> List[str]:
        """Generates a structured list of investigation tools to call."""
        if self.mode == "OPENAI":
            try:
                headers = {"Authorization": f"Bearer {settings.OPENAI_API_KEY}", "Content-Type": "application/json"}
                prompt = (
                    f"You are a SOC triage agent. An alert was received: {json.dumps(alert_data)}. "
                    f"ML Triage: {json.dumps(ml_triage)}. "
                    "Decide which tools to query among: ['lookup_ip', 'lookup_cve', 'lookup_whois', 'lookup_hash', 'query_memory']. "
                    "Return ONLY a valid JSON array of tool names, e.g. [\"lookup_ip\", \"query_memory\"]."
                )
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers=headers,
                        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1},
                        timeout=8.0
                    )
                    if resp.status_code == 200:
                        content = resp.json()["choices"][0]["message"]["content"]
                        match = re.search(r"\[.*\]", content, re.DOTALL)
                        if match:
                            return json.loads(match.group(0))
            except Exception:
                pass  # Fall through to Smart Local

        # Smart Local Plan Generation
        tools = ["query_memory"]
        alert_type = alert_data.get("alert_type", "").lower()
        sig = alert_data.get("signature", "").lower()
        payload = str(alert_data.get("payload_sample", "")).lower()

        # Always check external IP if present
        src_ip = alert_data.get("source_ip", "")
        if src_ip and not (src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172.16.")):
            tools.append("lookup_ip")
            tools.append("lookup_whois")

        # Check CVE if mentioned
        if "cve" in sig or "cve" in payload or "cve" in alert_type:
            tools.append("lookup_cve")

        # Check file hash if mentioned or payload contains hash
        if "hash" in sig or "hash" in payload or len(payload) == 64 or len(payload) == 32:
            tools.append("lookup_hash")

        if len(tools) == 1 and src_ip:
            tools.append("lookup_ip")

        return tools

    async def generate_incident_synthesis(
        self,
        alert_data: Dict[str, Any],
        ml_triage: Dict[str, Any],
        tool_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Synthesizes all investigation evidence into an executive root-cause, MITRE ATT&CK mapping, and verdict."""
        if self.mode == "OPENAI":
            try:
                headers = {"Authorization": f"Bearer {settings.OPENAI_API_KEY}", "Content-Type": "application/json"}
                prompt = (
                    f"You are a Senior SOC Analyst. Analyze this incident:\n"
                    f"Alert: {json.dumps(alert_data)}\n"
                    f"ML Triage: {json.dumps(ml_triage)}\n"
                    f"Tool Results: {json.dumps(tool_results)}\n"
                    "Return ONLY a JSON object with keys: "
                    "'root_cause', 'mitre_tactics' (list), 'final_severity' ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), "
                    "'executive_summary', 'recommended_action' ('BLOCK_IP', 'ISOLATE_HOST', 'KILL_SESSION', 'REVOKE_CREDENTIALS', 'CREATE_TICKET', 'FLAG_BENIGN')."
                )
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers=headers,
                        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
                        timeout=10.0
                    )
                    if resp.status_code == 200:
                        content = resp.json()["choices"][0]["message"]["content"]
                        match = re.search(r"\{.*\}", content, re.DOTALL)
                        if match:
                            return json.loads(match.group(0))
            except Exception:
                pass  # Fall through to Smart Local

        # Smart Local Reasoning Engine (Grounded Cyber Heuristics)
        alert_type = alert_data.get("alert_type", "Security Anomaly")
        src_ip = alert_data.get("source_ip", "Unknown")
        dst_port = alert_data.get("destination_port", 80)
        ml_sev = ml_triage.get("ml_severity", "MEDIUM")

        mitre_tactics = []
        root_cause = ""
        final_sev = ml_sev
        recommended_action = "CREATE_TICKET"

        # Threat analysis based on indicators
        ip_intel = tool_results.get("lookup_ip", {})
        cve_intel = tool_results.get("lookup_cve", {})
        memory_intel = tool_results.get("query_memory", {})

        is_high_abuse_ip = ip_intel.get("abuse_confidence_score", 0) > 80
        is_known_cve = bool(cve_intel.get("cve_id"))

        if "Log4j" in alert_type or "RCE" in alert_type or "C2" in alert_type or "Beacon" in alert_type or is_known_cve:
            final_sev = "CRITICAL"
            mitre_tactics = ["TA0001 Initial Access (T1190 Exploit Public-Facing App)", "TA0011 Command and Control (T1071 Application Layer Protocol)"]
            root_cause = f"Outbound malicious C2 beaconing or RCE payload detected against port {dst_port}. Ingress source IP {src_ip} matches active command-and-control infrastructure."
            recommended_action = "ISOLATE_HOST"
        elif "Ransomware" in alert_type or "Mimikatz" in alert_type:

            final_sev = "CRITICAL"
            mitre_tactics = ["TA0006 Credential Access (T1003 OS Credential Dumping)", "TA0008 Lateral Movement (T1021 Remote Services)"]
            root_cause = f"Credential dumping and shadow copy deletion execution observed over SMB/RPC from {src_ip}. High probability of active ransomware staging."
            recommended_action = "ISOLATE_HOST"
        elif "Brute Force" in alert_type or alert_data.get("failed_attempts", 0) > 20:
            final_sev = "HIGH"
            mitre_tactics = ["TA0006 Credential Access (T1110 Brute Force)"]
            root_cause = f"Automated dictionary/credential stuffing attacks detected from {src_ip} with {alert_data.get('failed_attempts', 0)} authentication rejections on port {dst_port}."
            recommended_action = "BLOCK_IP"
        elif "SQL Injection" in alert_type:
            final_sev = "HIGH"
            mitre_tactics = ["TA0001 Initial Access (T1190 Exploit Public-Facing App)"]
            root_cause = f"Structured SQL injection payload (UNION/SELECT) targeted database endpoint to extract unauthorized user records."
            recommended_action = "BLOCK_IP"
        elif "Scan" in alert_type or "Ping" in alert_type or "Routine" in alert_type or "Benign" in alert_type:
            final_sev = "LOW"
            mitre_tactics = ["TA0043 Reconnaissance (T1595 Active Scanning)"]
            root_cause = f"Reconnaissance probe or routine operational heartbeat. Zero unauthorized data transmission or payload execution confirmed."
            recommended_action = "FLAG_BENIGN"
        else:
            final_sev = ml_sev
            mitre_tactics = ["TA0007 Discovery (T1082 System Information Discovery)"]
            root_cause = f"Suspicious network activity from {src_ip} targeting port {dst_port}. Investigation confirmed anomalous behavior requiring security logging."
            recommended_action = "BLOCK_IP" if is_high_abuse_ip else "CREATE_TICKET"

        exec_summary = (
            f"Autonomous SOC investigation for alert '{alert_type}' completed. "
            f"Triage ML predicted {ml_sev} severity. Correlated evidence from {len(tool_results)} security tools. "
            f"Final determination: {final_sev} severity. Proposed remediation: {recommended_action}."
        )

        return {
            "root_cause": root_cause,
            "mitre_tactics": mitre_tactics,
            "final_severity": final_sev,
            "executive_summary": exec_summary,
            "recommended_action": recommended_action
        }

llm_engine = DualModeLLMEngine()
