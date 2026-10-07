import pandas as pd
import pytest

from src.rootguard.features import validate_features


def test_validate_features_normalizes_categorical_values():
    frame = pd.DataFrame(
        [
            {
                "latency_ms": "100",
                "cpu_usage": "55",
                "memory_usage": "63",
                "suspicious_port_count": "0",
                "deleted_process_count": "0",
                "failed_login_count": "2",
                "privilege_escalation_count": "0",
                "hidden_module": "1",
                "kernel_hook": "0",
                "lsmod_mismatch": "0",
                "syscall_table_modified": "0",
                "ld_preload_hook": "0",
                "library_injection": "0",
                "suid_binary": "0",
                "setuid_root": "0",
                "cron_persistence": "0",
                "startup_persistence": "0",
                "reverse_shell": "0",
                "bind_shell": "0",
                "unauthorized_listener": "0",
                "backdoor_port": "0",
                "log_tampering": "0",
                "history_cleared": "0",
                "audit_disabled": "0",
                "wtmp_deleted": "0",
            }
        ]
    )

    result = validate_features(frame)

    assert result.loc[0, "hidden_module"] == "1"
    assert result.loc[0, "kernel_hook"] == "0"
    assert result.loc[0, "latency_ms"] == 100


def test_validate_features_rejects_missing_columns():
    with pytest.raises(ValueError, match="Missing required feature columns"):
        validate_features(pd.DataFrame([{"latency_ms": 100}]))
