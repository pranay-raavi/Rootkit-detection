from src.rootguard.data import generate_synthetic_incidents
from src.rootguard.model import train_model
from src.rootguard.predict import predict_rootkit_risk


def test_training_pipeline_can_predict():
    data = generate_synthetic_incidents(n_samples=180, random_state=7)
    model, metrics = train_model(data, random_state=7)

    system_features = {
        "latency_ms": 900,
        "cpu_usage": 86,
        "memory_usage": 91,
        "suspicious_port_count": 4,
        "deleted_process_count": 2,
        "failed_login_count": 28,
        "privilege_escalation_count": 3,
        "hidden_module": 1,
        "kernel_hook": 1,
        "lsmod_mismatch": 1,
        "syscall_table_modified": 1,
        "ld_preload_hook": 1,
        "library_injection": 1,
        "suid_binary": 1,
        "setuid_root": 1,
        "cron_persistence": 1,
        "startup_persistence": 1,
        "reverse_shell": 1,
        "bind_shell": 0,
        "unauthorized_listener": 1,
        "backdoor_port": 1,
        "log_tampering": 1,
        "history_cleared": 1,
        "audit_disabled": 1,
        "wtmp_deleted": 1,
    }
    prediction, confidence = predict_rootkit_risk(model, system_features)

    assert prediction in {"normal", "rootkit"}
    assert 0 <= confidence <= 1
    assert metrics["accuracy"] > 0.65
