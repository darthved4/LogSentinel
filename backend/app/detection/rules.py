import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import unquote_plus

from app.detection.models import Finding
from app.models import EventCreate


@dataclass(frozen=True)
class RuleConfig:
    brute_force_attempts: int = 5
    brute_force_window_seconds: int = 60
    flood_requests: int = 30
    flood_window_seconds: int = 10
    reconnaissance_paths: int = 8
    reconnaissance_window_seconds: int = 60


SQL_INJECTION_PATTERNS = (
    re.compile(r"(?:'|%27)\s*(?:or|and)\s+['\d]", re.IGNORECASE),
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
    re.compile(r"(?:--|#|/\*)\s*$", re.IGNORECASE),
    re.compile(r"\b(?:drop|alter)\s+table\b", re.IGNORECASE),
)

LOGIN_MARKERS = ("/login", "/signin", "/auth", "authentication", "login")


def _largest_window(
    indexed_events: list[tuple[int, EventCreate]],
    window_seconds: int,
) -> list[tuple[int, EventCreate]]:
    ordered = sorted(indexed_events, key=lambda item: item[1].timestamp)
    active: deque[tuple[int, EventCreate]] = deque()
    largest: list[tuple[int, EventCreate]] = []
    window = timedelta(seconds=window_seconds)

    for item in ordered:
        active.append(item)
        while active and item[1].timestamp - active[0][1].timestamp > window:
            active.popleft()
        if len(active) > len(largest):
            largest = list(active)

    return largest


def _times(events: list[tuple[int, EventCreate]]) -> tuple:
    timestamps = [event.timestamp for _, event in events]
    return min(timestamps), max(timestamps)


class RuleEngine:
    def __init__(self, config: RuleConfig | None = None) -> None:
        self.config = config or RuleConfig()

    def detect(self, events: list[EventCreate]) -> list[Finding]:
        findings = []
        findings.extend(self._detect_brute_force(events))
        findings.extend(self._detect_sql_injection(events))
        findings.extend(self._detect_http_flood(events))
        findings.extend(self._detect_reconnaissance(events))
        return findings

    def _detect_brute_force(self, events: list[EventCreate]) -> list[Finding]:
        groups: dict[tuple[str, str], list[tuple[int, EventCreate]]] = defaultdict(list)
        for index, event in enumerate(events):
            searchable = f"{event.path or ''} {event.message} {event.raw}".lower()
            if (
                event.ip
                and event.status in {401, 403}
                and any(marker in searchable for marker in LOGIN_MARKERS)
            ):
                groups[(event.ip, event.user_agent or "unknown")].append((index, event))

        findings = []
        for (ip, _), grouped_events in groups.items():
            evidence = _largest_window(
                grouped_events, self.config.brute_force_window_seconds
            )
            if len(evidence) < self.config.brute_force_attempts:
                continue
            first_seen, last_seen = _times(evidence)
            findings.append(
                Finding(
                    detector="rule",
                    rule_id="LS-RULE-001",
                    type="brute_force",
                    severity="high",
                    confidence=0.98,
                    source_ip=ip,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_count=len(evidence),
                    evidence_indices=[index for index, _ in evidence],
                    mitre_techniques=["T1110 - Brute Force"],
                    summary=f"{len(evidence)} failed login attempts from {ip} within "
                    f"{self.config.brute_force_window_seconds} seconds.",
                    recommended_actions=[
                        "Temporarily rate-limit or block the source IP",
                        "Review targeted accounts and revoke suspicious sessions",
                    ],
                    metadata={"failed_attempts": len(evidence)},
                )
            )
        return findings

    def _detect_sql_injection(self, events: list[EventCreate]) -> list[Finding]:
        matches: dict[str, list[tuple[int, EventCreate, str]]] = defaultdict(list)
        for index, event in enumerate(events):
            text = unquote_plus(f"{event.path or ''} {event.message} {event.raw}")
            matched_pattern = next(
                (pattern.pattern for pattern in SQL_INJECTION_PATTERNS if pattern.search(text)),
                None,
            )
            if matched_pattern:
                matches[event.ip or "unknown"].append((index, event, matched_pattern))

        findings = []
        for ip, matched_events in matches.items():
            evidence = [(index, event) for index, event, _ in matched_events]
            first_seen, last_seen = _times(evidence)
            findings.append(
                Finding(
                    detector="rule",
                    rule_id="LS-RULE-002",
                    type="sql_injection",
                    severity="critical",
                    confidence=0.99,
                    source_ip=None if ip == "unknown" else ip,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_count=len(evidence),
                    evidence_indices=[index for index, _ in evidence],
                    mitre_techniques=[
                        "T1190 - Exploit Public-Facing Application"
                    ],
                    summary=f"SQL injection payload detected in {len(evidence)} request(s)"
                    + (f" from {ip}." if ip != "unknown" else "."),
                    recommended_actions=[
                        "Block or challenge the source IP",
                        "Inspect the targeted endpoint and use parameterized queries",
                    ],
                    metadata={
                        "matched_patterns": sorted(
                            {pattern for _, _, pattern in matched_events}
                        )
                    },
                )
            )
        return findings

    def _detect_http_flood(self, events: list[EventCreate]) -> list[Finding]:
        groups: dict[str, list[tuple[int, EventCreate]]] = defaultdict(list)
        for index, event in enumerate(events):
            if event.ip and event.method:
                groups[event.ip].append((index, event))

        findings = []
        for ip, grouped_events in groups.items():
            evidence = _largest_window(grouped_events, self.config.flood_window_seconds)
            if len(evidence) < self.config.flood_requests:
                continue
            first_seen, last_seen = _times(evidence)
            duration = max((last_seen - first_seen).total_seconds(), 1)
            request_rate = round(len(evidence) / duration, 2)
            latencies = [
                event.latency_ms
                for _, event in evidence
                if event.latency_ms is not None
            ]
            findings.append(
                Finding(
                    detector="rule",
                    rule_id="LS-RULE-003",
                    type="http_flood",
                    severity="critical",
                    confidence=0.97,
                    source_ip=ip,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_count=len(evidence),
                    evidence_indices=[index for index, _ in evidence],
                    mitre_techniques=["T1499 - Endpoint Denial of Service"],
                    summary=f"Traffic burst of {len(evidence)} requests from {ip} within "
                    f"{self.config.flood_window_seconds} seconds.",
                    recommended_actions=[
                        "Temporarily rate-limit the source IP",
                        "Enable endpoint protection mode and monitor recovery",
                    ],
                    metadata={
                        "request_rate_per_second": request_rate,
                        "average_latency_ms": round(sum(latencies) / len(latencies), 2)
                        if latencies
                        else None,
                    },
                )
            )
        return findings

    def _detect_reconnaissance(self, events: list[EventCreate]) -> list[Finding]:
        groups: dict[str, list[tuple[int, EventCreate]]] = defaultdict(list)
        for index, event in enumerate(events):
            if event.ip and event.path and event.status in {400, 401, 403, 404}:
                groups[event.ip].append((index, event))

        findings = []
        for ip, grouped_events in groups.items():
            evidence = _largest_window(
                grouped_events, self.config.reconnaissance_window_seconds
            )
            distinct_paths = {event.path for _, event in evidence}
            if len(distinct_paths) < self.config.reconnaissance_paths:
                continue
            first_seen, last_seen = _times(evidence)
            findings.append(
                Finding(
                    detector="rule",
                    rule_id="LS-RULE-004",
                    type="reconnaissance",
                    severity="medium",
                    confidence=0.94,
                    source_ip=ip,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_count=len(evidence),
                    evidence_indices=[index for index, _ in evidence],
                    mitre_techniques=["T1595 - Active Scanning"],
                    summary=f"Source {ip} probed {len(distinct_paths)} unavailable or "
                    "protected paths.",
                    recommended_actions=[
                        "Monitor or temporarily challenge the source IP",
                        "Review exposed routes and remove unnecessary endpoints",
                    ],
                    metadata={"distinct_paths": len(distinct_paths)},
                )
            )
        return findings

