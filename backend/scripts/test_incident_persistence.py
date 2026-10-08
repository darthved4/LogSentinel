import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.database import close_database, connect_database
from app.models import EventCreate
from app.pipeline import process_event_batch


async def main() -> None:
    database = await connect_database()
    batch_id = f"database-test-{uuid4()}"
    try:
        events = [
            EventCreate(
                asset_id="demo-store",
                timestamp=datetime(2026, 10, 8, tzinfo=timezone.utc)
                + timedelta(seconds=second),
                source="database-test",
                ip="203.0.113.66",
                method="POST",
                path="/login",
                status=401,
                latency_ms=30,
                user_agent="LogSentinel-Test",
                message="Login failed",
                raw="POST /login 401",
            )
            for second in range(5)
        ]
        result = await process_event_batch(
            database,
            events=events,
            ingestion_batch_id=batch_id,
        )
        assert len(result.event_ids) == 5
        assert len(result.incidents) == 1
        assert result.incidents[0].finding.type == "brute_force"
        assert len(result.incidents[0].evidence_event_ids) == 5
        print("Incident persistence test passed.")
    finally:
        await database.events.delete_many({"ingestion_batch_id": batch_id})
        await database.incidents.delete_many({"ingestion_batch_id": batch_id})
        await close_database()


if __name__ == "__main__":
    asyncio.run(main())
