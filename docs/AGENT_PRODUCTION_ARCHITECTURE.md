# ULPF Agent Production Architecture

## Objective

The ULPF Collector Agent provides local telemetry collection for
air-gapped and disconnected environments.

The agent is intentionally lightweight.

It does not perform deep log normalization.

## Architecture

Endpoint
    |
    +-- Linux log files
    +-- systemd journal
    +-- Windows Event Log
    +-- Application logs
    |
    v
ULPF Collector Agent
    |
    +-- Raw preservation
    +-- SHA-256
    +-- checkpointing
    +-- persistent spool
    +-- retry
    |
    v
Internal ULPF Gateway
    |
    v
Format Detection
    |
    v
Parser Registry
    |
    v
Universal Event Schema
    |
    v
Validation
    |
    v
Field-Level Lineage
    |
    v
Correlation
    |
    v
Alert Engine
    |
    +-- Dashboard
    +-- Forensics
    +-- SIEM
    +-- Data Lake

## Why parsing is centralized

Keeping parsers in the central ULPF avoids distributing hundreds of
parser implementations to every endpoint.

Agent updates therefore remain lightweight.

## Raw preservation

Every collected event contains:

- raw
- raw_hash
- source
- agent identity
- received timestamp

The raw value is preserved before normalization.

## Reliability

The agent uses:

- SQLite persistent spool
- checkpoint files
- retry
- batch forwarding
- restart recovery
- file truncation detection

If the gateway is unavailable, events remain locally queued.

## Air-gapped operation

No external cloud service is required.

The only network dependency is the configured internal ULPF gateway.

## Security

Recommended enterprise deployment:

- TLS
- preferably mTLS
- per-agent credentials
- least-privilege file access
- signed agent packages
- restricted outbound network policy
- controlled log source configuration

## Collection philosophy

ULPF should not indiscriminately collect every file.

OS telemetry is explicitly supported.

Application collection is administrator-configured.

This prevents accidental collection of unrelated sensitive files.