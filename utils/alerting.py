# utils/alerting.py

from typing import Dict, Any, List
import logging
# import requests # Uncomment if you implement actual webhooks like Slack

logger = logging.getLogger("ChainAnalyzer") # Use the logger from utils.logger

def check_alerts(risk_report: Dict[str, Any], config: Dict[str, Any]) -> List[str]:
    """
    Checks the risk report against configured thresholds and generates alerts.
    Can be extended to send notifications (e.g., Slack, email).
    """
    alerts = []
    risk_score = risk_report.get("score", 0)
    high_risk_threshold = config.get("risk_thresholds", {}).get("high_risk_score", 70)
    medium_risk_threshold = config.get("risk_thresholds", {}).get("medium_risk_score", 40)

    if risk_score >= high_risk_threshold:
        alert_message = f"HIGH RISK ALERT: Trace score {risk_score} exceeds threshold {high_risk_threshold}. Factors: {risk_report.get('factors', [])}"
        alerts.append(alert_message)
        logger.critical(alert_message)
        # _send_slack_notification(alert_message, config) # Example for actual notification
    elif risk_score >= medium_risk_threshold:
        alert_message = f"MEDIUM RISK ALERT: Trace score {risk_score} exceeds threshold {medium_risk_threshold}. Factors: {risk_report.get('factors', [])}"
        alerts.append(alert_message)
        logger.warning(alert_message)

    return alerts

# Example for sending Slack notifications (requires 'requests' and a webhook URL)
# def _send_slack_notification(message: str, config: Dict[str, Any]):
#     slack_enabled = config.get("alert_settings", {}).get("enable_slack", False)
#     slack_webhook_url = config.get("alert_settings", {}).get("slack_webhook_url", "")
#     
#     if slack_enabled and slack_webhook_url:
#         payload = {"text": message}
#         try:
#             response = requests.post(slack_webhook_url, json=payload, timeout=5)
#             response.raise_for_status()
#             logger.info("Slack notification sent successfully.")
#         except requests.exceptions.RequestException as e:
#             logger.error(f"Failed to send Slack notification: {e}")

