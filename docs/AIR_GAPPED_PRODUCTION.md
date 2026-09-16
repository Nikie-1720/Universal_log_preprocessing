# ULPF Air-Gapped Production Profile

ULPF is designed so the core collector, parser, normalizer, forensic lineage,
local AI onboarding baseline, SQLite/JSONL persistence and web console can run
without Internet access.

## Network boundary

The agent makes outbound requests only to the configured ULPF gateway. It does
not perform DNS discovery, cloud telemetry, package installation, remote model
calls or Internet scanning.

Optional local AI uses an Ollama endpoint only when `ULPF_LOCAL_AI=true`; the
endpoint must be loopback or RFC1918 private. Disable it for a fully deterministic
installation.

## Security profile

For production/private networks configure:

- HTTPS with a private CA.
- Optional client certificates (mTLS) on the agent.
- `ULPF_AGENT_TOKEN` for collector authentication.
- `ULPF_OPERATOR_TOKEN` for operator APIs.
- restrictive filesystem permissions for spool/raw evidence.
- a separate PostgreSQL instance when durable centralized storage is required.

SQLite + JSONL remain available for a self-contained disconnected deployment.

## Offline installation

The agent plugin itself uses only Python standard-library modules. The bundled
browser console is already built into `web/react-dist`, so normal runtime does
not require npm or an Internet connection.

Docker images must be built/imported before an air-gap is sealed; after that,
`docker compose` uses only the locally available images.
