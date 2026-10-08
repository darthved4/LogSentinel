import asyncio
from pathlib import Path
from uuid import uuid4

from app.database import close_database, connect_database
from app.ingestion.service import parse_log_file
from app.pipeline import process_event_batch


async def main() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    parsed = parse_log_file(repository_root / "sample-logs" / "attack_scenario.jsonl")
    assert len(parsed.events) == 51
    assert not parsed.errors

    database = await connect_database()
    batch_id = f"ingestion-test-{uuid4()}"
    try:
        result = await process_event_batch(
            database,
            parsed.events,
            ingestion_batch_id=batch_id,
        )
        assert len(result.event_ids) == 51
        assert result.incidents
        print(
            "Ingestion pipeline test passed: "
            f"{len(result.event_ids)} events, {len(result.incidents)} incidents."
        )
    finally:
        await database.events.delete_many({"ingestion_batch_id": batch_id})
        await database.incidents.delete_many({"ingestion_batch_id": batch_id})
        await close_database()


if __name__ == "__main__":
    asyncio.run(main())
