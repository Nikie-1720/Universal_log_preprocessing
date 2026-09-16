# ULPF — Universal Log Pre-processing Framework

ULPF is a vendor-agnostic preprocessing layer for perimeter/network security logs. It
preserves the exact raw event, detects the source/format, parses it with a registered
parser, normalizes vendor fields into a Universal Event Schema (UES), validates the
result, and records field lineage.

## What this release contains

- Syslog UDP/TCP receiver support in the core ingestion layer.
- File/directory/stdin ingestion in the core.
- Built-in parsers for Syslog, JSON, XML, CSV, CEF, LEEF, key/value and regex/plain text.
- Vendor parser configurations for Fortinet, Cisco ASA, Palo Alto, Nginx, Squid and SSH.
- Lossless raw event preservation with SHA-256 integrity metadata.
- Configuration-driven normalization.
- Field-level forensic lineage: original field/value, mapping rule, extraction method,
  confidence, parser and raw hash.
- Offline enrichment and local threat-intelligence support.
- Queryable local SQLite output for air-gapped demonstrations.
- Optional Elasticsearch/Kafka outputs retained from the original project.
- A zero-third-party-dependency web console with light/dark themes.
- One-command Docker deployment.
- A local system-log folder plus optional Linux `/var/log` mount.
- Offline onboarding suggestions and a ULPF Plugin Contract template.

## Hardened persistence and deployment

PostgreSQL is the authoritative store for normalized events, alerts, raw-evidence
metadata and correlation cases. Startup applies the idempotent schema and files in
`storage/migrations/`; duplicate event IDs and agent delivery fingerprints are
protected by unique indexes. `/api/live` is a liveness probe and `/api/ready`
requires PostgreSQL.

Copy `.env.example` to `.env` and set a unique `POSTGRES_PASSWORD` through a secret
manager before using Compose. No database password is shipped in source. Agent
write endpoints require `ULPF_AGENT_TOKEN`; HTTPS agents can use the optional
CA/client certificate settings in `agent/agent.yaml`. Raw evidence can be verified
through `GET /api/events/{trace_id}/verify` and exported from
`GET /api/events/export`.

## One-go run

Requirements: Docker Desktop / Docker Engine with Compose.

```bash
docker compose up --build
```

Then open:

```text
http://localhost:5173
```

The browser console has:
1. Sample log loading.
2. Raw log paste/upload from the browser.
3. Normalize events.
4. System-log normalization.
5. Normalized event stream.
6. Light/dark theme.
7. Click any normalized field to open the forensic lineage drawer.

The default demo does not require Elasticsearch, Kafka, an external LLM, or internet
access after the Docker image has been built.

## Test the golden path

In the console select **FortiGate traffic** and click **Normalize events**.

Expected normalized fields include:

```text
source.ip             = 192.168.1.25
source.port           = 51542
destination.ip        = 8.8.8.8
destination.port      = 443
network.transport     = tcp
action                = allow
destination.service   = HTTPS
device.vendor         = Fortinet
device.product        = FortiGate
```

Click `destination.port`. The forensic drawer shows the source field (`dstport`),
original value, mapping rule, extraction method, confidence and SHA-256-linked raw event.

## Run the CLI

The original command-line pipeline is still available:

```bash
python -m ulpf --help
python -m ulpf parse samples/fortigate-kv.log --pretty
```

or after installation:

```bash
pip install -e .
ulpf parse samples/fortigate-kv.log --pretty
```

The core package has no runtime third-party dependencies.

## System logs

The web console reads text-style system logs from:

- `/host-logs` when mounted (Linux host logs).
- `/var/log` inside the container.
- `./system-logs` included in this project.

To expose Linux host logs, uncomment this Compose volume:

```yaml
- /var/log:/host-logs:ro
```

Then click **Normalize system logs**.

Windows Event Log is not directly readable from a Linux Docker container. Export or
forward Windows events to a file/Syslog/agent first, then ingest that source.

## Architecture

```text
Network devices
      |
      v
Ingestion (Syslog / File / REST-style browser API)
      |
      v
Lossless Raw Event + SHA-256
      |
      v
Format + Vendor Detection
      |
      +---- Known ----> Plugin Registry
      |
      +---- Unknown --> Offline onboarding suggestions
                              |
                         human approval
                              |
                         plugin template
      |
      v
Parser
      |
      v
Field Extraction
      |
      v
Universal Normalization
      |
      +------> Explainability
      |
      +------> Validation / Quality
      |
      v
Field Lineage
      |
      v
Standardized UES Event
      |
      +----> SIEM
      +----> Data Lake
      +----> AI/ML
```

## Formal Plugin Contract

A vendor plugin is represented by a versioned package/configuration. The recommended
contract is:

```text
plugins/<vendor>/
├── manifest.yaml
├── parser.py
├── mappings.yaml
├── schema.yaml
└── tests/
    ├── sample.log
    └── expected.json
```

The existing parser registry is configuration-driven and loads parser specifications
from `configs/parsers/*.yaml`. This makes vendor onboarding independent from the ULPF
core.

The web API reports these plugins as `ULPF-Plugin-v1`.

## "Don't Replace — Augment"

ULPF is designed as a source-normalization layer. The normalized event can be adapted
to a downstream schema such as ECS, Splunk CIM, or a custom organization schema rather
than forcing a SIEM replacement.

```text
Heterogeneous network logs
          |
         ULPF
          |
 Universal Event Schema
          |
   +------+-------+
   |      |       |
  ECS    CIM    Custom
   |      |       |
 Existing SIEM / Data Lake / AI
```

## Air-gap positioning

The core parser/normalizer is standard-library Python. The web console is also served
by Python's standard-library HTTP server. Local files, local SQLite, local enrichment
feeds and optional local AI can therefore be used without a cloud dependency.

Docker makes the deployment reproducible. For a completely disconnected installation,
pre-load the built ULPF image (and any optional Elasticsearch/Kafka images) into the
target Docker host before starting Compose.

## Scaling

The core runtime already contains worker queues and batched outputs. Kafka is retained
as an optional high-volume sink. The architecture is intended to scale horizontally
with stateless processing workers. The hackathon prototype should demonstrate the
pipeline and explain horizontal scaling rather than claim that the local demo itself
processes billions of events/day.

## API endpoints

```text
GET  /api/health
GET  /api/events
GET  /api/events/{trace_id}/lineage
GET  /api/plugins
GET  /api/system-logs
GET  /api/stats
POST /api/normalize
POST /api/normalize-system
POST /api/onboarding/analyze
```

The frontend uses defensive response parsing so an empty/non-JSON backend response is
shown as a readable error instead of producing `Unexpected end of JSON input`.

## Important design principle

AI is an onboarding accelerator, not the production parser for every event.

```text
Unknown log
    |
offline/local analyzer
    |
suggest fields + mappings
    |
human approval
    |
deterministic plugin
    |
production events
```

This keeps high-volume processing deterministic, explainable and air-gap friendly.


# React Operator Console

ULPF now includes a richer React/Vite operator console in `frontend/`.

## Fastest demo (air-gap-safe runtime)

**Terminal 1 — ULPF engine**

```bash
docker compose up --build
```

Wait until the container reports the web console is listening, then open:

```text
http://localhost:5173
```

This mode uses the bundled Python console and requires no npm packages or internet at runtime.

## Stunning React console (recommended for the hackathon demo)

Keep Terminal 1 running:

```bash
docker compose up --build
```

**Terminal 2 — React**

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

The Vite development server proxies `/api/*` to the ULPF engine at `http://localhost:5173`, so both terminals use the same real processing pipeline and stored events.

### If `npm` is not recognized

Install Node.js 18+ / 20+ on the development machine, reopen the terminal, and verify:

```bash
node --version
npm --version
```

### Windows PowerShell

From the extracted project folder:

```powershell
docker compose up --build
```

Open a second PowerShell:

```powershell
cd frontend
npm install
npm run dev
```

Then browse to `http://localhost:3000`.

### macOS / Linux

Terminal 1:

```bash
cd ulpf_release
docker compose up --build
```

Terminal 2:

```bash
cd ulpf_release/frontend
npm install
npm run dev
```

Then browse to `http://localhost:3000`.

## Build React for an air-gapped package

On a connected build machine, run:

```bash
cd frontend
npm install
npm run build
cd ..
```

Then use the supplied packaging helper:

Linux/macOS:

```bash
bash scripts/build-react-and-package.sh
```

Windows PowerShell:

```powershell
.\scriptsuild-react-and-package.ps1
```

The resulting static React assets are copied to `web/react-dist/`. The Python server automatically prefers that directory when `web/react-dist/index.html` exists. You can then move the complete project/image into the restricted network; the browser no longer needs an external CDN.

## React console features

- Dark/light mode with persisted preference
- Animated pipeline health and event cards
- Lucide security/operations iconography
- Recharts activity visualization
- Searchable universal event stream
- Sample log selector for FortiGate, Cisco ASA, CEF, JSON and SSH/system syslog
- Real ULPF normalization API integration
- Click any normalized field to open forensic lineage
- Source field, original value, mapping rule, parser version and confidence
- SHA-256 raw-evidence view
- System-log normalization trigger
- Responsive layout for laptop/tablet screens

## Demo sequence

1. Start Docker in Terminal 1.
2. Start React in Terminal 2.
3. Open `http://localhost:3000`.
4. Choose **FortiGate traffic**.
5. Click **Run pipeline / Normalize**.
6. Show the normalized event.
7. Click `destination.port`.
8. Show `dstport → destination.port`, parser, confidence and raw evidence.
9. Click **System logs** to demonstrate local source ingestion.
10. Explain that the React UI is only the presentation layer; the deterministic ULPF engine, raw evidence and lineage remain the same.

## Production phases included in this release

- Phase 1: distributable ULPF Agent Plugin
- Phase 2: local OS/source discovery and capability reporting
- Phase 3: offline Agent configuration wizard
- Phase 4: token-authenticated registration/heartbeat/ingestion
- Phase 5: private-CA HTTPS and optional mTLS
- Phase 6: offline unknown-log onboarding + optional local-only Ollama assistance
- Phase 7: bounded requests, durable spool/checkpoints, atomic state and forensic integrity
- Phase 8: local benchmark + air-gap preflight + SIH demo documentation

### Air-gapped operation

For a completely disconnected installation, run the core with its local SQLite/JSONL
profile or import prebuilt Docker images before sealing the network. Runtime processing,
agent collection and deterministic onboarding do not require Internet access.
