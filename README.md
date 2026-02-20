# DriftWatch

Async endpoint diff scanner prototype built with FastAPI.

## Features
- Async streaming parser
- Snapshot diffing
- Incremental hashing
- Rate limiting
- Atomic disk writes

## Run

pip install -r requirements.txt
uvicorn server:app --reload
