from pathlib import Path

from app.ingestion.service import parse_log_file, parse_log_text


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_LOGS = REPOSITORY_ROOT / "sample-logs"


def test_json_asset_metadata_is_not_ingested_as_an_event() -> None:
    parsed = parse_log_file(SAMPLE_LOGS / "app_sample.json")

    assert len(parsed.events) == 2
    assert parsed.errors == []
    assert parsed.events[0].asset_id == "app-001"
    assert parsed.events[0].user == "jordan"
    assert parsed.events[0].path == "/v1/payments"


def test_nginx_parser_captures_request_fields() -> None:
    parsed = parse_log_file(SAMPLE_LOGS / "nginx_sample.log", log_format="nginx")

    assert len(parsed.events) == 3
    assert parsed.events[0].ip == "203.0.113.10"
    assert parsed.events[0].method == "POST"
    assert parsed.events[0].status == 401
    assert parsed.events[0].user_agent == "Mozilla/5.0"


def test_jsonl_reports_bad_lines_without_discarding_valid_events() -> None:
    parsed = parse_log_file(SAMPLE_LOGS / "jsonl_sample.txt")

    assert len(parsed.events) == 2
    assert len(parsed.errors) == 1
    assert parsed.errors[0]["location"] == "line 3"


def test_upload_text_path_uses_same_normalization_contract() -> None:
    text = (
        '{"timestamp":"2026-10-08T12:20:00Z","source":"app",'
        '"client_ip":"203.0.113.60","http_method":"GET",'
        '"url":"/health","status_code":200,"message":"ok"}'
    )
    parsed = parse_log_text(text, "uploaded.jsonl")

    assert len(parsed.events) == 1
    assert parsed.events[0].ip == "203.0.113.60"
    assert parsed.events[0].asset_id == "demo-store"


def test_attack_scenario_dataset_is_valid_jsonl() -> None:
    parsed = parse_log_file(SAMPLE_LOGS / "attack_scenario.jsonl")

    assert len(parsed.events) == 51
    assert parsed.errors == []
