import pytest
from classifier import IncidentClassifier, Incident, Severity, Category, ClassificationResult

@pytest.fixture
def clf():
    return IncidentClassifier()

def test_severity_p1_cpu(clf):
    inc = Incident(source="prometheus", title="High CPU on node-01", metric_name="cpu_usage", metric_value=92.0)
    r = clf.classify(inc)
    assert r.severity == Severity.P1
    assert r.category == Category.INFRA
    assert r.labels["notify_pagerduty"] == "true"

def test_severity_p2_memory(clf):
    inc = Incident(source="datadog", title="Memory pressure on host-3", metric_name="memory_usage", metric_value=88.0)
    r = clf.classify(inc)
    assert r.severity == Severity.P2
    assert r.category == Category.INFRA

def test_security_category_elevated(clf):
    inc = Incident(source="ids", title="Suspicious login attempt detected", description="Multiple unauthorized auth attempts")
    r = clf.classify(inc)
    assert r.category == Category.SECURITY
    assert r.severity in (Severity.P1, Severity.P2)

def test_app_error_rate(clf):
    inc = Incident(source="sentry", title="Error rate spike", metric_name="error_rate", metric_value=22.0)
    r = clf.classify(inc)
    assert r.severity == Severity.P2
    assert r.category == Category.APP

def test_network_packet_loss(clf):
    inc = Incident(source="snmp", title="Packet loss on gateway-2", metric_name="packet_loss_pct", metric_value=12.0)
    r = clf.classify(inc)
    assert r.severity == Severity.P2
    assert r.category == Category.NETWORK

def test_tag_override_severity(clf):
    inc = Incident(source="manual", title="Something", tags={"severity": "P4", "team": "app"})
    r = clf.classify(inc)
    assert r.severity == Severity.P4
    assert r.confidence == 1.0

def test_tag_override_category(clf):
    inc = Incident(source="jira", title="Disk filling up", tags={"team": "infra"})
    r = clf.classify(inc)
    assert r.category == Category.INFRA

def test_default_p3_fallback(clf):
    inc = Incident(source="cron", title="Routine check completed")
    r = clf.classify(inc)
    assert r.severity == Severity.P3
    assert r.category == Category.APP

def test_p4_never_notifies(clf):
    inc = Incident(source="manual", title="Low priority", tags={"severity": "P4"})
    r = clf.classify(inc)
    assert r.labels["notify_pagerduty"] == "false"
    assert r.labels["notify_slack"] == "false"

def test_p1_notifies_both(clf):
    inc = Incident(source="prometheus", title="Critical outage in production", metric_name="cpu_usage", metric_value=95.0)
    r = clf.classify(inc)
    assert r.labels["notify_pagerduty"] == "true"
    assert r.labels["notify_slack"] == "true"

def test_latency_p1(clf):
    inc = Incident(source="grafana", title="Latency spike on api-gateway", metric_name="latency_ms", metric_value=6000.0)
    r = clf.classify(inc)
    assert r.severity == Severity.P1

def test_disk_p3(clf):
    inc = Incident(source="node_exporter", title="Disk usage warning", metric_name="disk_usage", metric_value=78.0)
    r = clf.classify(inc)
    assert r.severity == Severity.P3