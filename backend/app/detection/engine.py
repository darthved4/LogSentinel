from app.detection.anomaly import AnomalyDetector
from app.detection.models import DetectionResult
from app.detection.rules import RuleEngine
from app.models import EventCreate


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class DetectionEngine:
    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        anomaly_detector: AnomalyDetector | None = None,
    ) -> None:
        self.rule_engine = rule_engine or RuleEngine()
        self.anomaly_detector = anomaly_detector

    def train_anomaly_detector(self, baseline_events: list[EventCreate]) -> int:
        if self.anomaly_detector is None:
            self.anomaly_detector = AnomalyDetector()
        return self.anomaly_detector.fit(baseline_events)

    def analyze(self, events: list[EventCreate]) -> DetectionResult:
        findings = self.rule_engine.detect(events)
        if self.anomaly_detector is not None:
            findings.extend(self.anomaly_detector.detect(events))
        findings.sort(key=lambda finding: SEVERITY_ORDER[finding.severity])
        return DetectionResult(events_analyzed=len(events), findings=findings)

