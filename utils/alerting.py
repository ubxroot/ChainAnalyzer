def check_alerts(risk_report, config):
    alerts = []
    if risk_report["score"] > config["risk_threshold"]:
        alerts.append("High risk score detected")
    return alerts
