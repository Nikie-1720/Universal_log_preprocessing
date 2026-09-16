# ULPF Phases 4–8 Release Notes

## Phase 4 — secure registration
Agent registration/heartbeat/ingest endpoints use a shared bearer token when
`ULPF_AGENT_TOKEN` is configured. Agent IDs are persistent and delivery records
carry a deterministic fingerprint for replay protection. Operator APIs can be
protected independently with `ULPF_OPERATOR_TOKEN`.

## Phase 5 — transport security
The web console supports HTTPS with a private CA and optional client-certificate
verification using `ULPF_TLS_CERT`, `ULPF_TLS_KEY`, `ULPF_TLS_CA` and
`ULPF_TLS_REQUIRE_CLIENT_CERT=true`. The agent already supports CA verification
and client certificates. Plain HTTP remains available for localhost development.

## Phase 6 — offline AI onboarding
`ulpf/local_ai.py` provides a deterministic semantic field mapper. Optional local
Ollama support is explicitly opt-in and restricted to loopback/RFC1918 addresses.
The UI can analyze an unknown log and generate a reviewable plugin package.
Generated plugins are not silently activated.

## Phase 7 — production hardening
The release includes bounded HTTP request bodies, durable local agent SQLite
spooling, checkpointed file offsets, restart-oriented system services, atomic
state writes, raw SHA-256 evidence, hash-chain archive manifests, bounded API
queries, operator authentication and structured health/readiness endpoints.

## Phase 8 — scale and demo readiness
`scripts/benchmark.py` measures local preprocessing throughput, average latency
and P95 latency without network calls. `scripts/preflight_airgap.py` performs a
static external-endpoint audit. `docs/DEMO_SCRIPT.md` contains the two-minute
SIH flow.

### Important scale claim
Do not claim a fixed billions/day throughput from this benchmark. Benchmark the
actual target hardware and deployment topology. Kafka/Elasticsearch/PostgreSQL
are optional scale-out components; SQLite/JSONL provide the self-contained
air-gapped path.
