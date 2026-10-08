"""Read log files and normalize records for ingestion."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


JsonRecord = dict[str, Any]
ParseError = dict[str, Any]


FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "time", "datetime"),
    "source": ("source", "service", "application"),
    "ip": ("ip", "client_ip", "remote_addr", "src_ip"),
    "method": ("method", "http_method"),
    "path": ("path", "url", "request_uri", "uri"),
    "status": ("status", "status_code", "http_status"),
    "user": ("user", "username", "account"),
    "user_agent": ("user_agent", "useragent", "http_user_agent"),
    "message": ("message", "msg", "event"),
    "asset_id": ("asset_id",),
    "latency_ms": ("latency_ms",),
}

ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/(?P<http_version>[\d.]+))?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)
AUTH_LOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) (?P<service>[^:]+): (?P<message>.*)$'
)
AUTH_USER_PATTERN = re.compile(r'for (?:invalid user )?(?P<user>\S+)')
AUTH_IP_PATTERN = re.compile(r' from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)')


def unwrap_extended_json(value: Any) -> Any:
    """Unwrap common MongoDB Extended JSON values, including nested values."""
    if isinstance(value, dict):
        wrappers = {
            "$date": lambda item: item,
            "$numberInt": int,
            "$numberLong": int,
            "$numberDouble": float,
            "$oid": str,
        }
        for key, converter in wrappers.items():
            if key in value and len(value) == 1:
                try:
                    return unwrap_extended_json(converter(value[key]))
                except (TypeError, ValueError):
                    return value[key]
        return {key: unwrap_extended_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [unwrap_extended_json(item) for item in value]
    return value


def normalize_timestamp(value: Any) -> str | None:
    """Return timestamps as ISO 8601 strings when they can be interpreted."""
    value = unwrap_extended_json(value)
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()

    text = str(value).strip()
    if not text:
        return None
    for parser in (
        lambda item: datetime.fromisoformat(item.replace("Z", "+00:00")),
        lambda item: datetime.strptime(item, "%d/%b/%Y:%H:%M:%S %z"),
        lambda item: datetime.strptime(item, "%b %d %H:%M:%S").replace(
            year=datetime.now(timezone.utc).year,
            tzinfo=timezone.utc,
        ),
    ):
        try:
            return parser(text).isoformat()
        except ValueError:
            continue
    return text


def first_value(record: JsonRecord, *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return unwrap_extended_json(value)
    return None


def normalize_status(value: Any) -> int | str | None:
    value = unwrap_extended_json(value)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


def is_asset_metadata(record: JsonRecord) -> bool:
    """Identify asset documents without mistaking named log events for assets."""
    has_asset_name = bool(record.get("name"))
    has_asset_marker = str(record.get("type", "")).lower() in {
        "asset",
        "asset_metadata",
    }
    has_event_fields = any(
        key in record
        for key in (
            "timestamp",
            "@timestamp",
            "time",
            "datetime",
            "message",
            "msg",
            "status",
            "status_code",
            "http_status",
            "path",
            "url",
            "request_uri",
            "uri",
        )
    )
    return bool(record.get("asset_id")) and has_asset_name and (
        has_asset_marker or not has_event_fields
    )


def _records_from_value(value: Any, errors: list[ParseError], location: str) -> list[JsonRecord]:
    if isinstance(value, dict):
        if "events" in value or "logs" in value:
            key = "events" if "events" in value else "logs"
            entries = value[key]
            if not isinstance(entries, list):
                errors.append({"location": location, "error": f"{key} must be an array", "raw": entries})
                return []
            value = entries
        else:
            value = [value]

    if not isinstance(value, list):
        errors.append({"location": location, "error": "record must be a JSON object", "raw": value})
        return []

    records: list[JsonRecord] = []
    for index, item in enumerate(value, start=1):
        if isinstance(item, dict):
            records.append(item)
        else:
            errors.append({
                "location": f"{location} item {index}",
                "error": "record must be a JSON object",
                "raw": item,
            })
    return records


def parse_nginx_line(line: str) -> JsonRecord | None:
    """Parse a standard Nginx combined access-log line."""
    match = ACCESS_LOG_PATTERN.match(line.strip())
    if not match:
        return None
    record = match.groupdict()
    record["source"] = "nginx"
    record["message"] = "HTTP request"
    record["raw"] = line
    return record


def parse_apache_line(line: str) -> JsonRecord | None:
    """Parse a standard Apache combined access-log line."""
    match = ACCESS_LOG_PATTERN.match(line.strip())
    if not match:
        return None
    record = match.groupdict()
    record["source"] = "apache"
    record["message"] = "HTTP request"
    record["raw"] = line
    return record


def parse_auth_line(line: str) -> JsonRecord | None:
    """Parse common sshd/syslog authentication lines."""
    match = AUTH_LOG_PATTERN.match(line.strip())
    if not match:
        return None
    record = match.groupdict()
    user_match = AUTH_USER_PATTERN.search(record["message"])
    ip_match = AUTH_IP_PATTERN.search(record["message"])
    record["source"] = "auth"
    record["user"] = user_match.group("user") if user_match else None
    record["ip"] = ip_match.group("ip") if ip_match else None
    record["raw"] = line
    return record


def _parse_json_lines(text: str) -> tuple[list[JsonRecord], list[ParseError]]:
    errors: list[ParseError] = []
    try:
        return _records_from_value(json.loads(text), errors, "JSON document"), errors
    except json.JSONDecodeError:
        records: list[JsonRecord] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                errors.append({
                    "location": f"line {line_number}",
                    "error": f"malformed JSON: {error.msg}",
                    "raw": line,
                })
                continue
            records.extend(_records_from_value(value, errors, f"line {line_number}"))
        return records, errors


def read_text_records(
    text: str, filename: str, log_format: str = "auto"
) -> tuple[list[JsonRecord], list[ParseError]]:
    """Read JSON, JSONL, Nginx, Apache, or auth records from uploaded text."""
    input_path = Path(filename)
    if input_path.suffix.lower() == ".json":
        return _parse_json_lines(text)

    selected_format = _format_from_path(input_path) if log_format == "auto" else log_format
    parser = {
        "nginx": parse_nginx_line,
        "apache": parse_apache_line,
        "auth": parse_auth_line,
    }.get(selected_format)
    if parser is None:
        raise ValueError(f"Unsupported log format: {selected_format}")

    records: list[JsonRecord] = []
    errors: list[ParseError] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if line.lstrip().startswith(("{", "[")):
            try:
                records.extend(
                    _records_from_value(json.loads(line), errors, f"line {line_number}")
                )
                continue
            except json.JSONDecodeError as error:
                errors.append(
                    {
                        "location": f"line {line_number}",
                        "error": f"malformed JSON: {error.msg}",
                        "raw": line,
                    }
                )
                continue
        record = parser(line)
        if record is None:
            errors.append(
                {
                    "location": f"line {line_number}",
                    "error": f"invalid {selected_format} log record",
                    "raw": line,
                }
            )
        else:
            records.append(record)
    return records, errors


def _format_from_path(input_path: Path) -> str:
    name = input_path.stem.lower()
    if "apache" in name:
        return "apache"
    if "auth" in name or "secure" in name:
        return "auth"
    return "nginx"


def read_records(input_path: Path, log_format: str = "auto") -> tuple[list[JsonRecord], list[ParseError]]:
    """Read JSON, JSONL, Nginx, Apache, or authentication log records."""
    text = input_path.read_text(encoding="utf-8-sig")
    return read_text_records(text, input_path.name, log_format=log_format)


def normalize_event(record: JsonRecord, assets: dict[str, JsonRecord]) -> JsonRecord:
    """Map a log record to the shared event shape while preserving its raw data."""
    asset_id = first_value(record, *FIELD_ALIASES["asset_id"])
    asset = assets.get(str(asset_id), {}) if asset_id is not None else {}
    normalized: JsonRecord = {
        "timestamp": normalize_timestamp(first_value(record, *FIELD_ALIASES["timestamp"])),
        "source": first_value(record, *FIELD_ALIASES["source"]) or "unknown",
        "ip": first_value(record, *FIELD_ALIASES["ip"]),
        "method": first_value(record, *FIELD_ALIASES["method"]),
        "path": first_value(record, *FIELD_ALIASES["path"]),
        "status": normalize_status(first_value(record, *FIELD_ALIASES["status"])),
        "user": first_value(record, *FIELD_ALIASES["user"]),
        "user_agent": first_value(record, *FIELD_ALIASES["user_agent"]),
        "message": first_value(record, *FIELD_ALIASES["message"]) or "Log event",
        "asset_id": asset_id or "demo-store",
        "raw": record.get("raw") or json.dumps(record, default=str),
    }

    latency = first_value(record, *FIELD_ALIASES["latency_ms"])
    if latency is not None:
        normalized["latency_ms"] = latency

    output_keys = {key for aliases in FIELD_ALIASES.values() for key in aliases}
    output_keys.update({"name", "type", "raw", "_raw"})
    for key, value in record.items():
        if key not in output_keys and key != "raw":
            normalized[key] = unwrap_extended_json(value)
    return normalized


def normalize_records(records: list[JsonRecord], errors: list[ParseError]) -> list[JsonRecord]:
    assets = {
        str(first_value(record, *FIELD_ALIASES["asset_id"])): record
        for record in records
        if is_asset_metadata(record)
    }
    return [
        normalize_event(record, assets)
        for record in records
        if not is_asset_metadata(record)
    ]
