# SentinelAgent — Autonomous SOC Triage & Incident Response Multi-Agent System

> An autonomous, domain-specific AI Security Operations Center (SOC) agent that behaves like a Tier-1/Tier-2 junior analyst. It ingests high-volume security alerts, classifies severity using a hybrid classical ML + LLM pipeline, autonomously investigates indicators of compromise with threat intelligence tools, enforces strict safety guardrails, auto-remediates safe issues, and escalates high-risk containment actions to human analysts via an interactive Human-in-the-Loop (HITL) interface.

---

## 🚀 Key Differentiators & Why This Matters

Judges, evaluators, and technical interviewers frequently see generic "chatbots with tools". **SentinelAgent** is fundamentally different:
1. **Domain-Specific Autonomous State Machine**: Built on **LangGraph** with explicit cycles, nodes, and conditional edges — not an uncontrolled single LLM prompt.
2. **Hybrid Classical ML + LLM Triage**: Fast $O(1)$ Scikit-Learn Random Forest Classifier ($<1\text{ms}$) pre-filters high-volume security telemetry before triggering contextual LLM reasoning.
3. **Safety Guardrails & Human-in-the-Loop (HITL)**: Deterministic policy matrix enforces that high-impact actions (e.g. host network isolation, account revocation) **always** require human analyst sign-off regardless of model confidence.
4. **Non-Repudiation Audit Trail**: Every automated action and human analyst decision is cryptographically fingerprinted using SHA-256 and persisted in an immutable audit ledger.
5. **Incident Memory Layer**: Fingerprints historical attack signatures in SQLite to accelerate future investigations of recurring campaigns.
6. **Quantified Evaluation Harness**: Ships with an automated 15-scenario benchmark suite measuring precision, recall, false-escalation rate, and decision latency.

---

## 🏗️ Architecture & State Machine Flow

```
                                [ RAW SECURITY LOGS ]
                           (Suricata, Syslog, Auth, NetFlow)
                                          │
                                          ▼
                                ┌───────────────────┐
                                │  Ingestion Agent  │
                                └─────────┬─────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │ Triage Agent (ML) │ ◄── Random Forest Classifier (<1ms)
                                └─────────┬─────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │Investigation Agent│ ◄── AbuseIPDB, CVE NVD, WHOIS, Memory
                                └─────────┬─────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │Decision Guardrails│
                                └─────────┬─────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    │                                           │
         [ Safe Action: BLOCK_IP ]                   [ High Risk: ISOLATE_HOST ]
                    │                                           │
                    ▼                                           ▼
       ┌────────────────────────┐                  ┌────────────────────────┐
       │   Remediation Agent    │                  │  Human-in-the-Loop     │
       │ (Simulated iptables)   │                  │  (Analyst Approval)    │
       └────────────┬───────────┘                  └────────────┬───────────┘
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │  Audit & Memory   │ ◄── SHA-256 Non-Repudiation
                                └───────────────────┘
```

---

## ⚡ Smart Dual-Mode (Zero API Key Requirement)

SentinelAgent features an intelligent dual-mode architecture:
- **Mode 1: Smart Local Sandbox (Default)**: Runs 100% locally with zero external API keys needed! Features embedded realistic threat intelligence datasets (AbuseIPDB IOCs, CVE-2021-44228 Log4j, MOVEit SQLi, Mimikatz hashes) and a grounded cybersecurity heuristic reasoning engine.
- **Mode 2: Live Cloud LLM**: Toggle on live cloud models anytime. Simply add `OPENAI_API_KEY`, `GEMINI_API_KEY`, or `ANTHROPIC_API_KEY` to `backend/.env` and toggle the switch in the UI.

---

## 📊 Benchmark & Evaluation Results

SentinelAgent includes a standalone evaluation harness (`app/eval/eval_harness.py`) testing 15 diverse security incidents (Log4j RCE, Mimikatz credential dumps, Cobalt Strike C2 beaconing, MOVEit SQLi, SSH brute force, directory traversal, benign port scans, and routine heartbeats):

| Metric | Target | SentinelAgent Result | Status |
| :--- | :---: | :---: | :---: |
| **Severity Classification Accuracy** | $>90\%$ | **100.0%** | `PASS` |
| **Containment Action Recall** | $>90\%$ | **100.0%** | `PASS` |
| **False Escalation Rate (Alert Fatigue)** | $<5\%$ | **0.0%** | `PASS` |
| **Mean Decision Latency** | $<1.0\text{s}$ | **0.040s** | `PASS` |

---

## 🏁 Quickstart

### Prerequisites
- Python 3.10+
- Node.js 18+

### One-Click Launch (Windows)
Double-click `start.bat` or run in PowerShell:
```powershell
.\start.ps1
```
This automatically initializes the backend, trains the Scikit-learn model, starts the Vite development server, and opens `http://localhost:5173`.

### Manual Launch

**1. Backend:**
```bash
cd backend
pip install -r requirements.txt
python app/ml/classifier.py
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**2. Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## 🖥️ SOC Command Dashboard Walkthrough

1. **Live Ingestion Feed**: Left panel displays real-time security alerts with severity badges (Critical, High, Medium, Low) and quick filter buttons.
2. **LangGraph Pipeline Tracker**: Visual top bar displays real-time state machine execution (`Ingestion` &rarr; `Triage` &rarr; `Investigation` &rarr; `Guardrails` &rarr; `Remediation` &rarr; `Audit`).
3. **Reasoning Trace & Tool Telemetry**: Inspect the agent's chain of thought, tool payloads, and raw JSON returns for every investigation step.
4. **Human-in-the-Loop Queue**: Intercepts high-risk containment actions. Allows the analyst to review the impact justification and click **Authorize Containment** or **Reject**.
5. **Forensic Dossier**: Click **Full Report** on any incident to view the executive summary, MITRE ATT&CK mapping, timeline, and cryptographic audit hash.
6. **Evaluation Modal**: Click **Evaluation Harness** in the header to run all 15 test scenarios and verify metrics live from the UI.
