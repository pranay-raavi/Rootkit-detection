from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from src.rootguard.config import SAMPLE_DATA_PATH


ROOTKIT_FLAGS = [
    "hidden_module",
    "kernel_hook",
    "lsmod_mismatch",
    "syscall_table_modified",
    "ld_preload_hook",
    "library_injection",
    "suid_binary",
    "setuid_root",
    "cron_persistence",
    "startup_persistence",
    "reverse_shell",
    "bind_shell",
    "unauthorized_listener",
    "backdoor_port",
    "log_tampering",
    "history_cleared",
    "audit_disabled",
    "wtmp_deleted",
]


def load_sample_data(path: Path = SAMPLE_DATA_PATH) -> pd.DataFrame:
    """Load the bundled starter dataset."""
    return pd.read_csv(path)


def generate_synthetic_incidents(n_samples: int = 1200, random_state: int = 42) -> pd.DataFrame:
    """Generate binary/numeric rootkit detection training data."""
    rng = np.random.default_rng(random_state)

    rows = []
    for _ in range(n_samples):
        is_rootkit = bool(rng.random() < 0.48)
        flag_probability = 0.36 if is_rootkit else 0.035
        flags = {
            flag: int(rng.random() < flag_probability)
            for flag in ROOTKIT_FLAGS
        }

        if is_rootkit:
            flags[rng.choice(ROOTKIT_FLAGS)] = 1
            flags[rng.choice(ROOTKIT_FLAGS)] = 1

        latency = rng.normal(740 if is_rootkit else 145, 130 if is_rootkit else 35)
        cpu = rng.normal(78 if is_rootkit else 38, 13 if is_rootkit else 9)
        memory = rng.normal(82 if is_rootkit else 48, 12 if is_rootkit else 10)
        suspicious_ports = rng.poisson(2.2 if is_rootkit else 0.15)
        deleted_processes = rng.poisson(1.0 if is_rootkit else 0.05)
        failed_logins = rng.poisson(18 if is_rootkit else 3)
        privilege_escalations = rng.poisson(1.4 if is_rootkit else 0.03)

        rows.append(
            {
                "latency_ms": round(float(np.clip(latency, 40, 1500)), 2),
                "cpu_usage": round(float(np.clip(cpu, 5, 100)), 2),
                "memory_usage": round(float(np.clip(memory, 10, 100)), 2),
                "suspicious_port_count": int(suspicious_ports),
                "deleted_process_count": int(deleted_processes),
                "failed_login_count": int(failed_logins),
                "privilege_escalation_count": int(privilege_escalations),
                **flags,
                "label": "rootkit" if is_rootkit else "normal",
            }
        )

    return pd.DataFrame(rows)
