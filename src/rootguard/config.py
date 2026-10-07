from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
MODEL_DIR = PROJECT_ROOT / "models"

SAMPLE_DATA_PATH = DATA_DIR / "rootkit_features.csv"
MODEL_PATH = MODEL_DIR / "rootguard_pipeline.joblib"

TARGET_COLUMN = "label"

NUMERIC_FEATURES = [
    "latency_ms",
    "cpu_usage",
    "memory_usage",
    "suspicious_port_count",
    "deleted_process_count",
    "failed_login_count",
    "privilege_escalation_count",
]

CATEGORICAL_FEATURES = [
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

FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES
