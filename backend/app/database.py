from pymongo import ASCENDING, DESCENDING, AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from app.config import get_settings


_client: AsyncMongoClient | None = None
_database: AsyncDatabase | None = None


async def connect_database() -> AsyncDatabase:
    global _client, _database

    settings = get_settings()
    _client = AsyncMongoClient(
        settings.mongodb_uri,
        serverSelectionTimeoutMS=5_000,
    )
    await _client.admin.command("ping")
    _database = _client[settings.mongodb_database]
    await create_indexes(_database)
    return _database


async def create_indexes(database: AsyncDatabase) -> None:
    await database.events.create_index(
        [("asset_id", ASCENDING), ("timestamp", DESCENDING)],
        name="asset_timestamp",
    )
    await database.events.create_index(
        [("ip", ASCENDING), ("timestamp", DESCENDING)],
        name="ip_timestamp",
    )
    desired_incident_status_index = [
        ("status", ASCENDING),
        ("finding.last_seen", DESCENDING),
    ]
    existing_indexes = await database.incidents.index_information()
    existing_status_index = existing_indexes.get("status_last_seen")
    if existing_status_index and existing_status_index["key"] != desired_incident_status_index:
        # This exact name was created by the initial prototype with an obsolete key path.
        # It contains no data and is safely replaced with the nested incident field index.
        await database.incidents.drop_index("status_last_seen")
    await database.incidents.create_index(
        desired_incident_status_index,
        name="status_last_seen",
    )
    await database.incidents.create_index(
        [("fingerprint", ASCENDING)], name="unique_incident_fingerprint", unique=True
    )
    await database.incidents.create_index(
        [("ingestion_batch_id", ASCENDING), ("created_at", DESCENDING)],
        name="batch_created_at",
    )
    await database.denylist.create_index(
        [("asset_id", ASCENDING), ("type", ASCENDING), ("value", ASCENDING)],
        name="unique_denylist_target",
        unique=True,
    )


def get_database() -> AsyncDatabase:
    if _database is None:
        raise RuntimeError("Database has not been connected yet.")
    return _database


async def close_database() -> None:
    global _client, _database

    if _client is not None:
        await _client.close()
    _client = None
    _database = None
