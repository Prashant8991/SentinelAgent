import asyncio
import json
import time
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from typing import Dict, Any, List
from app.agents.graph import soc_agent_graph


EVAL_DATA_PATH = Path(__file__).resolve().parent / "eval_dataset.json"

async def evaluate_all_incidents() -> Dict[str, Any]:
    with open(EVAL_DATA_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    results = []
    total_start = time.time()

    correct_severity = 0
    correct_action = 0
    false_escalations = 0
    benign_count = 0
    latencies = []

    for item in dataset:
        start_t = time.time()
        initial_state = {
            "incident_id": f"eval_run_{item['id']}",
            "alert": item["alert"],
            "timeline": [],
            "trace_events": []
        }

        final = await soc_agent_graph.ainvoke(initial_state)
        latency = round((time.time() - start_t), 3)
        latencies.append(latency)

        pred_sev = final["synthesis"]["final_severity"]
        pred_action = final.get("proposed_actions", [{}])[0].get("action_type", "CREATE_TICKET")
        hitl_triggered = final["hitl_required"]

        is_sev_match = (pred_sev == item["ground_truth_severity"])
        is_action_match = (pred_action == item["ground_truth_action"])

        is_benign = item["ground_truth_severity"] in ["LOW", "INFO"]
        is_false_esc = is_benign and hitl_triggered

        if is_sev_match:
            correct_severity += 1
        if is_action_match:
            correct_action += 1
        if is_benign:
            benign_count += 1
            if is_false_esc:
                false_escalations += 1

        results.append({
            "id": item["id"],
            "name": item["scenario_name"],
            "ground_truth_severity": item["ground_truth_severity"],
            "predicted_severity": pred_sev,
            "ground_truth_action": item["ground_truth_action"],
            "predicted_action": pred_action,
            "hitl_triggered": hitl_triggered,
            "latency_sec": latency,
            "severity_match": is_sev_match,
            "action_match": is_action_match,
            "false_escalation": is_false_esc
        })

    total_time = round(time.time() - total_start, 2)
    n = len(dataset)
    sev_acc = round((correct_severity / n) * 100, 1)
    act_acc = round((correct_action / n) * 100, 1)
    false_esc_rate = round((false_escalations / max(1, benign_count)) * 100, 1)
    avg_latency = round(sum(latencies) / max(1, len(latencies)), 3)

    summary = {
        "total_test_cases": n,
        "severity_accuracy_pct": sev_acc,
        "action_accuracy_pct": act_acc,
        "false_escalation_rate_pct": false_esc_rate,
        "average_latency_sec": avg_latency,
        "total_benchmark_time_sec": total_time,
        "detailed_results": results
    }

    return summary

def print_evaluation_report(summary: Dict[str, Any]):
    print("\n=======================================================")
    print("      SENTINELAGENT EVALUATION & BENCHMARK HARNESS     ")
    print("=======================================================")
    print(f"Total Test Cases Evaluated : {summary['total_test_cases']}")
    print(f"Severity Classification Acc: {summary['severity_accuracy_pct']}%")
    print(f"Action Recommendation Acc  : {summary['action_accuracy_pct']}%")
    print(f"False Escalation Rate      : {summary['false_escalation_rate_pct']}% (Target: <5%)")
    print(f"Average Decision Latency   : {summary['average_latency_sec']}s")
    print(f"Total Benchmark Runtime    : {summary['total_benchmark_time_sec']}s")
    print("-------------------------------------------------------")
    print(f"{'Scenario':<38} | {'True':<8} | {'Pred':<8} | {'HITL':<5} | {'Match'}")
    print("-------------------------------------------------------")
    for r in summary["detailed_results"]:
        match_icon = "[PASS]" if (r["severity_match"] and r["action_match"]) else "[DIFF]"
        print(f"{r['name'][:38]:<38} | {r['ground_truth_severity']:<8} | {r['predicted_severity']:<8} | {str(r['hitl_triggered']):<5} | {match_icon}")
    print("=======================================================\n")


if __name__ == "__main__":
    summary = asyncio.run(evaluate_all_incidents())
    print_evaluation_report(summary)

