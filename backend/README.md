# LogSentinel backend

## Database test

From the `backend` directory:

1. Create a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and replace `MONGODB_URI` with the Atlas connection string.

4. Run the round-trip database test:

   ```powershell
python -m scripts.test_database
```

Verify database-backed incident persistence:

```powershell
python -m scripts.test_incident_persistence
```

## Run the API

```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` to test the API interactively.

## Detection engine

Run the detector test suite:

```powershell
python -m pytest -q
```

Run a simulated attack through the rule and ML engines:

```powershell
python -m scripts.test_engine
```

The batch detection endpoint is `POST /api/detect`. It accepts a JSON array of normalized
events and returns structured findings. Rule-based findings are authoritative; the Isolation
Forest model supplies an additional behavioral-anomaly signal after it has been trained on
baseline traffic.

## Ingestion integration

The ingestion layer should call `app.pipeline.process_event_batch(database, events)` after it
has parsed a file into `list[EventCreate]`. The function assigns an upload batch ID, stores all
events, runs detection, and persists deduplicated incidents. It returns the batch ID, MongoDB
event IDs, and created incident records.
