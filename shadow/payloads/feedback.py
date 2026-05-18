"""Payload feedback loop — analyzes responses and generates variants for anomalies."""

from dataclasses import dataclass
from shadow.payloads.engine import AdaptivePayloadEngine, Payload


@dataclass
class ResponseData:
    status_code: int
    body: str = ""
    headers: dict = None
    response_time_ms: float = 0.0
    content_length: int = 0

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.content_length == 0 and self.body:
            self.content_length = len(self.body)


@dataclass
class FeedbackSignal:
    has_anomaly: bool
    anomaly_type: str = "none"   # timing_spike / status_change / error_message / length_change
    anomaly_details: dict = None
    variants: list = None

    def __post_init__(self):
        if self.anomaly_details is None:
            self.anomaly_details = {}
        if self.variants is None:
            self.variants = []


class PayloadFeedback:
    TIMING_SPIKE_MULTIPLIER = 2.0   # response > 2x baseline = timing spike
    LENGTH_CHANGE_THRESHOLD = 0.30  # 30% change in response length

    def __init__(self, engine: AdaptivePayloadEngine, baseline: ResponseData = None):
        self.engine = engine
        self.baseline = baseline

    def analyze_response(self, payload: Payload, response: ResponseData) -> FeedbackSignal:
        """Analyze response for anomalies. Returns FeedbackSignal with variants if anomaly found."""
        anomalies = self._detect_anomalies(response)

        if not anomalies:
            return FeedbackSignal(has_anomaly=False)

        # Use first anomaly type
        anomaly_type = anomalies[0]["type"]
        anomaly_details = anomalies[0]

        # Generate variants from the successful payload
        variants = self.engine.generate_variants(payload, anomaly_details)

        return FeedbackSignal(
            has_anomaly=True,
            anomaly_type=anomaly_type,
            anomaly_details=anomaly_details,
            variants=variants,
        )

    def set_baseline(self, baseline: ResponseData) -> None:
        self.baseline = baseline

    def _detect_anomalies(self, response: ResponseData) -> list[dict]:
        anomalies = []

        if self.baseline is None:
            return anomalies

        # Timing spike
        if (self.baseline.response_time_ms > 0 and
                response.response_time_ms > self.baseline.response_time_ms * self.TIMING_SPIKE_MULTIPLIER):
            anomalies.append({
                "type": "timing_spike",
                "baseline_ms": self.baseline.response_time_ms,
                "observed_ms": response.response_time_ms,
            })

        # Status code change
        if response.status_code != self.baseline.status_code:
            anomalies.append({
                "type": "status_change",
                "baseline_status": self.baseline.status_code,
                "observed_status": response.status_code,
            })

        # Error message in body
        error_keywords = ["error", "exception", "syntax", "warning", "fatal", "undefined"]
        body_lower = response.body.lower()
        if (any(kw in body_lower for kw in error_keywords) and
                not any(kw in self.baseline.body.lower() for kw in error_keywords)):
            anomalies.append({
                "type": "error_message",
                "keywords_found": [kw for kw in error_keywords if kw in body_lower],
            })

        # Response length change > 30%
        if self.baseline.content_length > 0:
            change = abs(response.content_length - self.baseline.content_length) / self.baseline.content_length
            if change > self.LENGTH_CHANGE_THRESHOLD:
                anomalies.append({
                    "type": "length_change",
                    "baseline_length": self.baseline.content_length,
                    "observed_length": response.content_length,
                    "change_pct": round(change * 100, 1),
                })

        return anomalies
