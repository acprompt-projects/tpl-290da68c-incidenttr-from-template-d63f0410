import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import httpx

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ChannelConfig:
    slack_webhook_url: Optional[str] = None
    pagerduty_routing_key: Optional[str] = None
    pagerduty_api_url: str = "https://events.pagerduty.com/v2/enqueue"
    email_smtp_host: Optional[str] = None
    email_smtp_port: int = 587
    email_from: Optional[str] = None
    email_to: list = field(default_factory=list)
    email_user: Optional[str] = None
    email_pass: Optional[str] = None


class RateLimiter:
    def __init__(self, max_calls: int = 10, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        self._timestamps[key] = [t for t in self._timestamps[key] if t > cutoff]
        if len(self._timestamps[key]) >= self.max_calls:
            return False
        self._timestamps[key].append(now)
        return True


class RoutingRules:
    DEFAULT_RULES = {
        Severity.CRITICAL: ["slack", "pagerduty", "email"],
        Severity.HIGH: ["slack", "pagerduty"],
        Severity.MEDIUM: ["slack", "email"],
        Severity.LOW: ["slack"],
        Severity.INFO: ["slack"],
    }

    def __init__(
        self,
        severity_routes: Optional[dict[Severity, list[str]]] = None,
        category_overrides: Optional[dict[str, dict[Severity, list[str]]]] = None,
    ):
        self.severity_routes = severity_routes or self.DEFAULT_RULES
        self.category_overrides = category_overrides or {}

    def resolve(self, incident: Incident) -> list[str]:
        if incident.category in self.category_overrides:
            cat_rules = self.category_overrides[incident.category]
            if incident.severity in cat_rules:
                return cat_rules[incident.severity]
        return self.severity_routes.get(incident.severity, ["slack"])


class SlackDispatcher:
    def __init__(self, webhook_url: str, client: Optional[httpx.Client] = None):
        self.webhook_url = webhook_url
        self._client = client or httpx.Client(timeout=10.0)

    def send(self, incident: Incident) -> bool:
        severity_emoji = {
            Severity.CRITICAL: "🔴", Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡", Severity.LOW: "🟢", Severity.INFO: "⚪",
        }
        payload = {
            "text": f"{severity_emoji.get(incident.severity, '⚪')} *[{incident.severity.value.upper()}]* {incident.title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{incident.title}*\n*Severity:* {incident.severity.value} | *Category:* {incident.category}\n{incident.description}"}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Incident ID: `{incident.id}`"}]},
            ],
        }
        try:
            resp = self._client.post(self.webhook_url, json=payload)
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Slack dispatch failed for %s: %s", incident.id, exc)
            return False


class PagerDutyDispatcher:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue", client: Optional[httpx.Client] = None):
        self.routing_key = routing_key
        self.api_url = api_url
        self._client = client or httpx.Client(timeout=10.0)

    def send(self, incident: Incident) -> bool:
        severity_map = {
            Severity.CRITICAL: "critical", Severity.HIGH: "critical",
            Severity.MEDIUM: "warning", Severity.LOW: "warning", Severity.INFO: "info",
        }
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "severity": severity_map.get(incident.severity, "warning"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.id,
                "custom_details": {"description": incident.description, **incident.metadata},
            },
        }
        try:
            resp = self._client.post(self.api_url, json=payload)
            resp.raise_for_status()
            logger.info("PagerDuty alert sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("PagerDuty dispatch failed for %s: %s", incident.id, exc)
            return False


class EmailDispatcher:
    def __init__(self, smtp_host: str, smtp_port: int, from_addr: str, to_addrs: list, user: Optional[str] = None, password: Optional[str] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.user = user
        self.password = password

    def send(self, incident: Incident) -> bool:
        import smtplib
        from email.mime.text import MIMEText
        subject = f"[{incident.severity.value.upper()}] {incident.title} ({incident.category})"
        body = f"Incident: {incident.title}\nID: {incident.id}\nSeverity: {incident.severity.value}\nCategory: {incident.category}\n\n{incident.description}"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as srv:
                if self.user and self.password:
                    srv.starttls()
                    srv.login(self.user, self.password)
                srv.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            logger.info("Email sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Email dispatch failed for %s: %s", incident.id, exc)
            return False


class NotificationDispatcher:
    def __init__(self, config: ChannelConfig, routing_rules: Optional[RoutingRules] = None, rate_limiter: Optional[RateLimiter] = None):
        self.config = config
        self.routing = routing_rules or RoutingRules()
        self.rate_limiter = rate_limiter or RateLimiter()
        self._channels: dict[str, object] = {}
        if config.slack_webhook_url:
            self._channels["slack"] = SlackDispatcher(config.slack_webhook_url)
        if config.pagerduty_routing_key:
            self._channels["pagerduty"] = PagerDutyDispatcher(config.pagerduty_routing_key, config.pagerduty_api_url)
        if config.email_smtp_host and config.email_from and config.email_to:
            self._channels["email"] = EmailDispatcher(config.email_smtp_host, config.email_smtp_port, config.email_from, config.email_to, config.email_user, config.email_pass)

    def dispatch(self, incident: Incident) -> dict[str, bool]:
        channels = self.routing.resolve(incident)
        results: dict[str, bool] = {}
        for ch_name in channels:
            handler = self._channels.get(ch_name)
            if not handler:
                logger.warning("Channel %s not configured, skipping incident %s", ch_name, incident.id)
                results[ch_name] = False
                continue
            rate_key = f"{ch_name}:{incident.category}:{incident.severity.value}"
            if not self.rate_limiter.allow(rate_key):
                logger.warning("Rate limited channel %s for incident %s", ch_name, incident.id)
                results[ch_name] = False
                continue
            results[ch_name] = handler.send(incident)
        return results