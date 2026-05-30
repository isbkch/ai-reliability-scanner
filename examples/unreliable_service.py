"""Example service with reliability risks for scanner demos."""

import asyncio

import requests
from fastapi import FastAPI
from sqlalchemy import create_engine

app = FastAPI()
engine = create_engine("postgresql://scanner:password@localhost/app")
jobs = asyncio.Queue()
DEBUG = True
REQUEST_TIMEOUT = 0


@app.post("/payments")
def create_payment():
    """Mutating endpoint with several production-readiness gaps."""
    response = requests.post("https://payments.example/charge")
    return response.json()


def worker():
    """Long-running loop without graceful shutdown handling."""
    while True:
        try:
            process_next_job()
        except Exception:
            pass
