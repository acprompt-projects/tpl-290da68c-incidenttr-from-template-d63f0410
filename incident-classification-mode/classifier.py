import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"

@dataclass
class ClassificationResult:
    severity: Severity
    category: Category
    confidence: float
    labels: dict = field(default_factory=dict)
    reason: str = ""

@dataclass
class Incident:
    source: str
    title: str
    description: str = ""
    metric_name: str = ""
    metric_value: float = 0.0
    tags: dict = field(default_factory=dict)
    raw_alert: dict = field(default_factory=dict)

SEVERITY_THRESHOLDS = {
    "cpu_usage": {90.0: Severity.P1, 75.0: Severity.P2, 50.0: Severity.P3},
    "memory_usage": {95.0: Severity.P1, 85.0: Severity.P2, 70.0: Severity.P3},
    "disk_usage": {98.0: Severity.P1, 90.0: Severity.P2, 75.0: Severity.P3},
    "error_rate": {50.0: Severity.P1, 20.0: Severity.P2, 5.0: Severity.P3},
    "latency_ms": {5000.0: Severity.P1, 2000.0: Severity.P2, 500.0: Severity.P3},
    "packet_loss_pct": {25.0: Severity.P1, 10.0: Severity.P2, 2.0: Severity.P3},
}

CATEGORY_KEYWORDS = {
    Category.INFRA: [
        r"\bcpu\b", r"\bmemory\b", r"\bram\b", r"\bdisk\b", r"\bstorage\b",
        r"\bhost\b", r"\bserver\b", r"\bnode\b", r"\bvm\b", r"\boom\b",
        r"\bpod\b", r"\bcontainer\b", r"\bkube\b", r"\bdeploy\b",
    ],
    Category.APP: [
        r"\berror\b", r"\bexception\b", r"\bcrash\b", r"\b500\b", r"\b502\b",
        r"\b503\b", r"\blatency\b", r"\btimeout\b", r"\bslow\b",
        r"\bresponse.?time\b", r"\bthroughput\b", r"\bhang\b",
    ],
    Category.SECURITY: [
        r"\bbreach\b", r"\bunauthorized\b", r"\bauth\b", r"\blogin\b",
        r"\bcsrf\b", r"\bxss\b", r"\binjection\b", r"\bmalware\b",
        r"\bvuln\b", r"\bcve\b", r"\bfirewall\b", r"\bintrusion\b",
        r"\bpermission\b", r"\bexploit\b", r"\bransomware\b",
    ],
    Category.NETWORK: [
        r"\bnetwork\b", r"\bconnection\b", r"\bdns\b", r"\brouting\b",
        r"\bpacket\b", r"\bbandwidth\b", r"\blink\b", r"\bgateway\b",
        r"\btcp\b", r"\budp\b", r"\bssl\b", r"\btls\b", r"\bvpn\b",
        r"\bping\b", r"\bpacket.?loss\b",
    ],
}

CATEGORY_TAG_OVERRIDES = {
    "team:infra": Category.INFRA,
    "team:platform": Category.INFRA,
    "team:app": Category.APP,
    "team:backend": Category.APP,
    "team:security": Category.SECURITY,
    "team:netops": Category.NETWORK,
    "team:sre": Category.INFRA,
}

SEVERITY_TAG_OVERRIDES = {
    "severity:P1": Severity.P1,
    "severity:P2": Severity.P2,
    "severity:P3": Severity.P3,
    "severity:P4": Severity.P4,
    "priority:critical": Severity.P1,
    "priority:high": Severity.P2,
    "priority:medium": Severity.P3,
    "priority:low": Severity.P4,
}


class IncidentClassifier:
    def __init__(
        self,
        severity_thresholds: dict = None,
        category_keywords: dict = None,
    ):
        self.thresholds = severity_thresholds or SEVERITY_THRESHOLDS
        self.keywords = category_keywords or CATEGORY_KEYWORDS
        self._compiled: dict = {}
        for cat, patterns in self.keywords.items():
            self._compiled[cat] = [re.compile(p, re.IGNORECASE) for p in patterns]

    def classify(self, incident: Incident) -> ClassificationResult:
        category, cat_conf, cat_reason = self._determine_category(incident)
        severity, sev_conf, sev_reason = self._determine_severity(incident, category)
        confidence = round((cat_conf * 0.4 + sev_conf * 0.6), 3)
        labels = self._build_labels(severity, category, incident)
        reason = f"{sev_reason}; {cat_reason}"
        return ClassificationResult(
            severity=severity,
            category=category,
            confidence=confidence,
            labels=labels,
            reason=reason,
        )

    def _determine_category(self, inc: Incident):
        for tag_key, cat in CATEGORY_TAG_OVERRIDES.items():
            k, v = tag_key.split(":", 1)
            if inc.tags.get(k) == v:
                return cat, 1.0, f"tag override '{tag_key}'"
        text = f"{inc.title} {inc.description}".strip()
        scores: dict = {}
        for cat, compiled_list in self._compiled.items():
            hits = sum(1 for pat in compiled_list if pat.search(text))
            if hits:
                scores[cat] = min(hits / len(compiled_list), 1.0)
        if scores:
            best = max(scores, key=scores.get)
            conf = 0.5 + scores[best] * 0.5
            return best, round(conf, 3), f"keyword match score={scores[best]:.2f}"
        return Category.APP, 0.3, "default fallback (no keywords matched)"

    def _determine_severity(self, inc: Incident, cat: Category):
        for tag_key, sev in SEVERITY_TAG_OVERRIDES.items():
            k, v = tag_key.split(":", 1)
            if inc.tags.get(k) == v:
                return sev, 1.0, f"tag override '{tag_key}'"
        if inc.metric_name and inc.metric_name in self.thresholds:
            thresholds = self.thresholds[inc.metric_name]
            for boundary in sorted(thresholds.keys(), reverse=True):
                if inc.metric_value >= boundary:
                    sev = thresholds[boundary]
                    conf = round(0.6 + 0.4 * (1.0 - boundary / max(thresholds.keys())), 3)
                    return sev, conf, f"{inc.metric_name}={inc.metric_value}>={boundary}"
        p1_words = ["critical", "outage", "down", "unrecoverable"]
        p2_words = ["degraded", "failing", "high", "escalate"]
        text = f"{inc.title} {inc.description}".lower()
        if any(w in text for w in p1_words):
            return Severity.P1, 0.65, "title/description contains P1 keyword"
        if any(w in text for w in p2_words):
            return Severity.P2, 0.60, "title/description contains P2 keyword"
        if cat == Category.SECURITY:
            return Severity.P2, 0.55, "security category default elevation to P2"
        return Severity.P3, 0.40, "default P3 (no specific signal)"

    def _build_labels(self, sev: Severity, cat: Category, inc: Incident) -> dict:
        labels = {
            "severity": sev.value,
            "category": cat.value,
            "triage_source": inc.source,
        }
        if inc.metric_name:
            labels["metric"] = inc.metric_name
            labels["metric_value"] = str(inc.metric_value)
        notify = sev in (Severity.P1, Severity.P2)
        labels["notify_pagerduty"] = str(sev == Severity.P1).lower()
        labels["notify_slack"] = str(notify).lower()
        return labels