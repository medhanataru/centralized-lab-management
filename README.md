# Centralized Lab Management System

A client-server REST API system built in Python for real-time lab computer health monitoring and secure package distribution over a TCP/IP network.

## Features
- **Real-Time Telemetry:** Clients (`client.py`) collect CPU, RAM, and disk metrics via `psutil` and report them over HTTP/JSON to a central Flask server (`server.py`).
- **Role-Based Access Control:** Secures endpoints using `X-API-Key` headers (`hmac`) separating standard lab nodes from administrator views (`admin.py`).
- **Integrity-Verified File Distribution:** Distributes approved files over `/api/packages` and verifies downloads via **SHA-256** checksums (`hashlib`) to discard corrupted files.
- **Persistence & Fault Tolerance:** Stores historical logs in **SQLite**, enforces 16 KB payload limits, validates inputs, and handles network timeouts gracefully.

## Architecture & Files
- `server.py` — Flask REST API handling ingestion, threshold alerts (`HEALTHY` / `WARNING`), authentication, and package serving.
- `client.py` — Background agent reporting system metrics and downloading/verifying approved packages.
- `admin.py` — CLI admin viewer to inspect live machine status and alert logs.
- `config.json` — Configuration for host, port, API keys, resource thresholds, and approved package hashes.
