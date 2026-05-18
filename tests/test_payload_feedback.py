"""Tests for PayloadFeedback."""

import pytest
from shadow.payloads.engine import AdaptivePayloadEngine, Payload
from shadow.payloads.feedback import PayloadFeedback, ResponseData, FeedbackSignal


def make_baseline(status=200, body="Hello World", time_ms=100.0):
    return ResponseData(status_code=status, body=body, response_time_ms=time_ms)


def make_payload():
    return Payload(raw="' OR 1=1--", vuln_class="sqli")


class TestPayloadFeedback:
    @pytest.fixture
    def feedback(self):
        engine = AdaptivePayloadEngine()
        baseline = make_baseline()
        return PayloadFeedback(engine, baseline=baseline)

    def test_no_anomaly_normal_response(self, feedback):
        response = ResponseData(status_code=200, body="Hello World", response_time_ms=110.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert not signal.has_anomaly
        assert signal.anomaly_type == "none"

    def test_timing_spike_detected(self, feedback):
        response = ResponseData(status_code=200, body="Hello World", response_time_ms=5000.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert signal.has_anomaly
        assert signal.anomaly_type == "timing_spike"

    def test_status_change_detected(self, feedback):
        response = ResponseData(status_code=500, body="Hello World", response_time_ms=100.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert signal.has_anomaly
        assert signal.anomaly_type == "status_change"

    def test_length_change_detected(self, feedback):
        response = ResponseData(status_code=200, body="A" * 1000, response_time_ms=100.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert signal.has_anomaly
        assert signal.anomaly_type == "length_change"

    def test_error_message_detected(self, feedback):
        response = ResponseData(status_code=200, body="SQL syntax error near 'admin'", response_time_ms=100.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert signal.has_anomaly
        assert signal.anomaly_type == "error_message"

    def test_anomaly_generates_variants(self, feedback):
        response = ResponseData(status_code=500, body="Hello World", response_time_ms=100.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert signal.has_anomaly
        assert len(signal.variants) > 0
        assert all(isinstance(v, Payload) for v in signal.variants)

    def test_no_anomaly_when_no_baseline(self):
        engine = AdaptivePayloadEngine()
        fb = PayloadFeedback(engine, baseline=None)
        response = ResponseData(status_code=500, body="error", response_time_ms=5000.0)
        signal = fb.analyze_response(make_payload(), response)
        assert not signal.has_anomaly

    def test_set_baseline(self):
        engine = AdaptivePayloadEngine()
        fb = PayloadFeedback(engine)
        assert fb.baseline is None
        fb.set_baseline(make_baseline())
        assert fb.baseline is not None

    def test_timing_spike_threshold(self, feedback):
        # 199ms — just under 2x baseline of 100ms — no spike
        response = ResponseData(status_code=200, body="Hello World", response_time_ms=199.0)
        signal = feedback.analyze_response(make_payload(), response)
        assert not signal.has_anomaly

        # 201ms — just over 2x — spike
        response2 = ResponseData(status_code=200, body="Hello World", response_time_ms=201.0)
        signal2 = feedback.analyze_response(make_payload(), response2)
        assert signal2.has_anomaly
