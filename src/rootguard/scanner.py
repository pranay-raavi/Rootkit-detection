from __future__ import annotations

import re
from dataclasses import dataclass

from src.rootguard.config import FEATURE_COLUMNS


@dataclass(frozen=True)
class Indicator:
    name: str
    pattern: str
    severity: int
    explanation: str


INDICATORS = [
    Indicator(
        name="Hidden module flag",
        pattern=r"\b(hidden_module|kernel_hook|lsmod_mismatch|syscall_table_modified)\s*[:=]\s*1\b",
        severity=3,
        explanation="A binary security flag shows possible kernel hiding or syscall tampering.",
    ),
    Indicator(
        name="Preload hook flag",
        pattern=r"\b(ld_preload_hook|preload_hook|library_injection)\s*[:=]\s*1\b",
        severity=3,
        explanation="A binary security flag shows possible command/library hooking.",
    ),
    Indicator(
        name="Persistence flag",
        pattern=r"\b(cron_persistence|startup_persistence|suid_binary|setuid_root)\s*[:=]\s*1\b",
        severity=3,
        explanation="A binary security flag shows possible persistence or privilege abuse.",
    ),
    Indicator(
        name="Backdoor flag",
        pattern=r"\b(reverse_shell|bind_shell|unauthorized_listener|backdoor_port)\s*[:=]\s*1\b",
        severity=3,
        explanation="A binary security flag shows possible remote access or backdoor activity.",
    ),
    Indicator(
        name="Log tampering flag",
        pattern=r"\b(log_tampering|history_cleared|audit_disabled|wtmp_deleted)\s*[:=]\s*1\b",
        severity=2,
        explanation="A binary security flag shows possible evidence removal.",
    ),
    Indicator(
        name="Kernel module hiding",
        pattern=r"\b(hidden module|module hidden|lsmod mismatch|unknown kernel module)\b",
        severity=3,
        explanation="Hidden or unknown kernel modules can indicate kernel-level tampering.",
    ),
    Indicator(
        name="LD_PRELOAD hook",
        pattern=r"\b(ld_preload|/etc/ld\.so\.preload|preload hook)\b",
        severity=3,
        explanation="LD_PRELOAD abuse can intercept normal system commands.",
    ),
    Indicator(
        name="Suspicious privileged binary",
        pattern=r"\b(suid shell|chmod 4777|setuid root|/bin/bash -p)\b",
        severity=3,
        explanation="Unexpected privileged binaries can provide persistent root access.",
    ),
    Indicator(
        name="Deleted process binary",
        pattern=r"\b\(deleted\)|deleted executable|process binary missing\b",
        severity=2,
        explanation="Processes running from deleted binaries are commonly seen in stealthy malware.",
    ),
    Indicator(
        name="Network backdoor",
        pattern=r"\b(reverse shell|bind shell|nc -l|netcat listener|unauthorized listener)\b",
        severity=3,
        explanation="Unexpected listeners or shell connections can indicate remote control.",
    ),
    Indicator(
        name="Log tampering",
        pattern=r"\b(log cleared|audit log disabled|history cleared|wtmp deleted|auth\.log modified)\b",
        severity=2,
        explanation="Attackers often clear logs to hide activity.",
    ),
    Indicator(
        name="Known rootkit term",
        pattern=r"\b(chkrootkit warning|rkhunter warning|diamorphine|reptile|adore-ng|rootkit-like persistence|rootkit risk detected)\b",
        severity=3,
        explanation="The report contains known rootkit-related terms or tool warnings.",
    ),
    Indicator(
        name="Cron persistence",
        pattern=r"\b(cron persistence|suspicious cron|@reboot.*(curl|wget|bash|sh))\b",
        severity=2,
        explanation="Suspicious cron entries can restart malware after reboot.",
    ),
]


def _extract_numeric_signals(text: str) -> dict[str, float]:
    signals: dict[str, float] = {}
    for key, value in re.findall(
        r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(-?\d+(?:\.\d+)?)\b",
        text,
    ):
        signals[key.lower()] = float(value)
    return signals


def parse_feature_text(text: str) -> dict[str, object]:
    """Parse key=value feature text into the model feature schema."""
    signals = _extract_numeric_signals(text)
    parsed = {}
    for column in FEATURE_COLUMNS:
        parsed[column] = int(signals.get(column, 0)) if column != "latency_ms" else signals.get(column, 0)

    for column in ["cpu_usage", "memory_usage"]:
        parsed[column] = signals.get(column, 0)

    for column in [
        "suspicious_port_count",
        "deleted_process_count",
        "failed_login_count",
        "privilege_escalation_count",
    ]:
        parsed[column] = int(signals.get(column, 0))

    return parsed


def _score_numeric_signals(signals: dict[str, float]) -> list[dict[str, object]]:
    findings = []
    checks = [
        (
            "High suspicious port count",
            "suspicious_port_count",
            3,
            2,
            "Multiple suspicious ports can indicate unauthorized listeners.",
        ),
        (
            "High deleted process count",
            "deleted_process_count",
            1,
            2,
            "Processes with deleted binaries can indicate stealthy execution.",
        ),
        (
            "High privilege escalation count",
            "privilege_escalation_count",
            1,
            3,
            "Privilege escalation events can indicate attacker activity.",
        ),
        (
            "High latency anomaly",
            "latency_ms",
            700,
            1,
            "Very high latency can be a supporting anomaly during compromise.",
        ),
        (
            "High failed login count",
            "failed_login_count",
            10,
            1,
            "Many failed logins can indicate brute-force or suspicious access attempts.",
        ),
    ]

    for name, key, threshold, severity, explanation in checks:
        value = signals.get(key)
        if value is not None and value >= threshold:
            findings.append(
                {
                    "indicator": name,
                    "severity": severity,
                    "matches": 1,
                    "explanation": f"{explanation} Found {key}={value:g}.",
                }
            )

    return findings


def scan_text(text: str) -> dict[str, object]:
    """Scan a text report for rootkit-like indicators.

    This is a lightweight explainable scanner for demo and learning purposes.
    It is not a replacement for a professional EDR or forensic investigation.
    """
    matches = []
    risk_score = 0

    for indicator in INDICATORS:
        found = re.findall(indicator.pattern, text, flags=re.IGNORECASE)
        if found:
            risk_score += indicator.severity
            matches.append(
                {
                    "indicator": indicator.name,
                    "severity": indicator.severity,
                    "matches": len(found),
                    "explanation": indicator.explanation,
                }
            )

    numeric_findings = _score_numeric_signals(_extract_numeric_signals(text))
    matches.extend(numeric_findings)
    risk_score += sum(int(finding["severity"]) for finding in numeric_findings)

    if risk_score >= 7:
        risk_level = "High"
        verdict = "Rootkit risk detected"
    elif risk_score >= 3:
        risk_level = "Medium"
        verdict = "Suspicious activity found"
    elif risk_score > 0:
        risk_level = "Low"
        verdict = "Low risk indicators found"
    else:
        risk_level = "Clean"
        verdict = "No rootkit risk detected"

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "indicators_found": matches,
        "lines_scanned": len(text.splitlines()),
        "characters_scanned": len(text),
    }
