"""Log parsing and validation for the shared ingestion pipeline."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from app.database import close_database, connect_database
from app.ingestion.parsers import normalize_records, read_records, read_text_records
from app.models import EventCreate
from app.pipeline import BatchProcessingResult, process_event_batch


@dataclass
class ParsedLogBatch:
    events: list[EventCreate]
    errors: list[dict[str, Any]]


class IngestionResponse(BaseModel):
    filename: str
    accepted_events: int
    rejected_records: int
    parse_errors: list[dict[str, Any]]
    batch: BatchProcessingResult


def _validate_events(
    normalized_records: list[dict[str, Any]], errors: list[dict[str, Any]]
) -> list[EventCreate]:
    events = []
    for index, record in enumerate(normalized_records, start=1):
        try:
            events.append(EventCreate.model_validate(record))
        except ValidationError as error:
            errors.append(
                {
                    "location": f"normalized event {index}",
                    "error": "failed schema validation",
                    "details": error.errors(include_url=False),
                    "raw": record,
                }
            )
    return events


def parse_log_file(input_path: Path, log_format: str = "auto") -> ParsedLogBatch:
    records, errors = read_records(input_path, log_format=log_format)
    normalized_records = normalize_records(records, errors)
    return ParsedLogBatch(_validate_events(normalized_records, errors), errors)


def parse_log_text(text: str, filename: str, log_format: str = "auto") -> ParsedLogBatch:
    records, errors = read_text_records(text, filename, log_format=log_format)
    normalized_records = normalize_records(records, errors)
    return ParsedLogBatch(_validate_events(normalized_records, errors), errors)


async def ingest_file(
    input_path: Path, log_format: str = "auto"
) -> tuple[ParsedLogBatch, BatchProcessingResult]:
    parsed = parse_log_file(input_path, log_format=log_format)
    if not parsed.events:
        raise ValueError("No valid events were found in the uploaded log file")
    database = await connect_database()
    try:
        result = await process_event_batch(database, parsed.events)
    finally:
        await close_database()
    return parsed, result


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a log file into LogSentinel.")
    parser.add_argument("input_path", type=Path, help="Log file to parse and ingest")
    parser.add_argument(
        "--format",
        choices=("auto", "nginx", "apache", "auth"),
        default="auto",
        help="Text log format; auto selects from the file name",
    )
    args = parser.parse_args()
    if not args.input_path.is_file():
        parser.error(f"input file does not exist: {args.input_path}")

    try:
        parsed, result = asyncio.run(ingest_file(args.input_path, args.format))
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))

    print(f"Accepted {len(parsed.events)} events; rejected {len(parsed.errors)} records.")
    print(f"Batch ID: {result.ingestion_batch_id}")
    print(f"Created or matched {len(result.incidents)} incidents.")


if __name__ == "__main__":
    main()
