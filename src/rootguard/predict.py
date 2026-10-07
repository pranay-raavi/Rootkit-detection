from __future__ import annotations

import argparse

import pandas as pd

from src.rootguard.features import validate_features
from src.rootguard.model import load_model


def predict_rootkit_risk(model, system_features: dict[str, object]) -> tuple[str, float]:
    frame = validate_features(pd.DataFrame([system_features]))
    probabilities = model.predict_proba(frame)[0]
    classes = model.classes_
    best_index = int(probabilities.argmax())
    return str(classes[best_index]), float(probabilities[best_index])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict whether rootkit risk exists.")
    parser.add_argument("--latency-ms", type=float, required=True)
    parser.add_argument("--cpu", type=float, required=True)
    parser.add_argument("--memory", type=float, required=True)
    parser.add_argument("--hidden-module", type=int, choices=[0, 1], default=0)
    parser.add_argument("--ld-preload-hook", type=int, choices=[0, 1], default=0)
    parser.add_argument("--reverse-shell", type=int, choices=[0, 1], default=0)
    parser.add_argument("--log-tampering", type=int, choices=[0, 1], default=0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    system_features = {
        "latency_ms": args.latency_ms,
        "cpu_usage": args.cpu,
        "memory_usage": args.memory,
        "suspicious_port_count": 0,
        "deleted_process_count": 0,
        "failed_login_count": 0,
        "privilege_escalation_count": 0,
        "hidden_module": args.hidden_module,
        "kernel_hook": 0,
        "lsmod_mismatch": 0,
        "syscall_table_modified": 0,
        "ld_preload_hook": args.ld_preload_hook,
        "library_injection": 0,
        "suid_binary": 0,
        "setuid_root": 0,
        "cron_persistence": 0,
        "startup_persistence": 0,
        "reverse_shell": args.reverse_shell,
        "bind_shell": 0,
        "unauthorized_listener": 0,
        "backdoor_port": 0,
        "log_tampering": args.log_tampering,
        "history_cleared": 0,
        "audit_disabled": 0,
        "wtmp_deleted": 0,
    }

    model = load_model()
    prediction, confidence = predict_rootkit_risk(model, system_features)
    print(f"Predicted class: {prediction}")
    print(f"Confidence: {confidence:.2%}")


if __name__ == "__main__":
    main()
