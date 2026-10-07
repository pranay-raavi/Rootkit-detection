from src.rootguard.scanner import scan_text


def test_scan_text_returns_clean_result_for_normal_report():
    result = scan_text(
        """
        System Health Report
        Open ports reviewed: only expected services are running.
        Authentication logs checked: no suspicious login activity.
        Cron jobs reviewed: no unknown startup task.
        """
    )

    assert result["risk_level"] == "Clean"
    assert result["verdict"] == "No rootkit risk detected"
    assert result["risk_score"] == 0
    assert result["indicators_found"] == []


def test_scan_text_detects_rootkit_indicators():
    result = scan_text(
        """
        rkhunter warning: suspicious file properties found.
        Unknown kernel module observed.
        /etc/ld.so.preload contains unexpected preload hook.
        Possible reverse shell discovered.
        auth.log modified and shell history cleared.
        """
    )

    assert result["risk_level"] == "High"
    assert result["verdict"] == "Rootkit risk detected"
    assert result["risk_score"] >= 7
    assert len(result["indicators_found"]) >= 3


def test_scan_text_detects_binary_feature_flags():
    result = scan_text(
        """
        hidden_module=1
        ld_preload_hook=1
        reverse_shell=1
        log_tampering=1
        latency_ms=930
        suspicious_port_count=3
        privilege_escalation_count=2
        """
    )

    assert result["risk_level"] == "High"
    assert result["verdict"] == "Rootkit risk detected"
    assert result["risk_score"] >= 7
