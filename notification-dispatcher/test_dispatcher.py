import pytest
from unittest.mock import MagicMock, patch
from dispatcher import (
    NotificationDispatcher, ChannelConfig, Incident, Severity,
    RoutingRules, RateLimiter, SlackDispatcher, PagerDutyDispatcher,
)

INCIDENT = Incident(id="inc-1", title="DB connection pool exhausted", severity=Severity.CRITICAL, category="database", description="Primary DB unreachable")
LOW_INCIDENT = Incident(id="inc-2", title="Disk usage 75%", severity=Severity.LOW, category="infra", description="Threshold warning")


class TestRoutingRules:
    def test_default_critical_routes_to_all(self):
        rules = RoutingRules()
        assert set(rules.resolve(INCIDENT)) == {"slack", "pagerduty", "email"}

    def test_default_low_routes_to_slack_only(self):
        rules = RoutingRules()
        assert rules.resolve(LOW_INCIDENT) == ["slack"]

    def test_category_override(self):
        rules = RoutingRules(category_overrides={"database": {Severity.LOW: ["pagerduty"]}})
        db_low = Incident(id="inc-3", title="Slow query", severity=Severity.LOW, category="database", description="")
        assert rules.resolve(db_low) == ["pagerduty"]


class TestRateLimiter:
    def test_allows_within_limit(self):
        rl = RateLimiter(max_calls=3, window_seconds=60)
        assert all(rl.allow("key") for _ in range(3))

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_calls=2, window_seconds=60)
        rl.allow("key")
        rl.allow("key")
        assert rl.allow("key") is False

    def test_per_key_independent(self):
        rl = RateLimiter(max_calls=1, window_seconds=60)
        assert rl.allow("a") is True
        assert rl.allow("b") is True
        assert rl.allow("a") is False


class TestSlackDispatcher:
    def test_send_success(self):
        with patch("dispatcher.httpx.Client") as MockClient:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_client = MagicMock()
            mock_client.post.return_value = mock_resp
            MockClient.return_value = mock_client
            sd = SlackDispatcher("https://hooks.slack.test/x")
            assert sd.send(INCIDENT) is True
            mock_client.post.assert_called_once()


class TestPagerDutyDispatcher:
    def test_send_success(self):
        with patch("dispatcher.httpx.Client") as MockClient:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_client = MagicMock()
            mock_client.post.return_value = mock_resp
            MockClient.return_value = mock_client
            pd = PagerDutyDispatcher("routing-key-123")
            assert pd.send(INCIDENT) is True
            call_args = mock_client.post.call_args
            payload = call_args[1]["json"]
            assert payload["payload"]["severity"] == "critical"


class TestNotificationDispatcher:
    def test_dispatch_routes_by_severity(self):
        config = ChannelConfig(slack_webhook_url="https://hooks.slack.test/x", pagerduty_routing_key="rk")
        with patch("dispatcher.httpx.Client") as MockClient:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_client = MagicMock()
            mock_client.post.return_value = mock_resp
            MockClient.return_value = mock_client
            nd = NotificationDispatcher(config)
            results = nd.dispatch(INCIDENT)
            assert "slack" in results
            assert "pagerduty" in results

    def test_dispatch_skips_unconfigured_channel(self):
        config = ChannelConfig(pagerduty_routing_key="rk")
        with patch("dispatcher.httpx.Client") as MockClient:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_client = MagicMock()
            mock_client.post.return_value = mock_resp
            MockClient.return_value = mock_client
            nd = NotificationDispatcher(config)
            results = nd.dispatch(INCIDENT)
            assert results.get("slack") is False

    def test_dispatch_respects_rate_limit(self):
        config = ChannelConfig(slack_webhook_url="https://hooks.slack.test/x")
        rl = RateLimiter(max_calls=0, window_seconds=60)
        with patch("dispatcher.httpx.Client") as MockClient:
            MockClient.return_value = MagicMock()
            nd = NotificationDispatcher(config, rate_limiter=rl)
            results = nd.dispatch(LOW_INCIDENT)
            assert results.get("slack") is False