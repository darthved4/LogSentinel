import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / ".env")


@dataclass(frozen=True)
class Settings:
    mongodb_uri: str
    mongodb_database: str


def get_settings() -> Settings:
    mongodb_uri = os.getenv("MONGODB_URI", "").strip()
    mongodb_database = os.getenv("MONGODB_DATABASE", "logsentinel").strip()

    if not mongodb_uri:
        raise RuntimeError(
            "MONGODB_URI is missing. Copy backend/.env.example to backend/.env "
            "and add your MongoDB Atlas connection string."
        )

    return Settings(
        mongodb_uri=mongodb_uri,
        mongodb_database=mongodb_database,
    )

