-- ULPF schema is intentionally idempotent.  Keep this table first so an
-- upgrade can be applied repeatedly by every web/agent process.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    trace_id TEXT PRIMARY KEY,
    event_id TEXT,
    event_time TIMESTAMPTZ,
    ingest_time TIMESTAMPTZ,
    received_time TIMESTAMPTZ,

    source_type TEXT,
    source_address TEXT,
    transport TEXT,

    parser TEXT,
    parser_version TEXT,

    pipeline_id TEXT,
    pipeline_version TEXT,

    format TEXT,
    parse_status TEXT,

    severity INTEGER,
    severity_label TEXT,

    vendor TEXT,
    product TEXT,

    agent_id TEXT,

    raw_hash TEXT,
    raw_size BIGINT,
    raw_path TEXT,

    schema_version TEXT,

    event_json JSONB NOT NULL,
    meta_json JSONB,
    ues_json JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_event_time
    ON events(event_time);

CREATE INDEX IF NOT EXISTS idx_events_ingest_time
    ON events(ingest_time);

CREATE INDEX IF NOT EXISTS idx_events_source_type
    ON events(source_type);

CREATE INDEX IF NOT EXISTS idx_events_source_address
    ON events(source_address);

CREATE INDEX IF NOT EXISTS idx_events_agent_id
    ON events(agent_id);

CREATE INDEX IF NOT EXISTS idx_events_parser
    ON events(parser);

CREATE INDEX IF NOT EXISTS idx_events_severity
    ON events(severity);

CREATE INDEX IF NOT EXISTS idx_events_raw_hash
    ON events(raw_hash);

CREATE INDEX IF NOT EXISTS idx_events_event_json
    ON events USING GIN(event_json);

ALTER TABLE events ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();


CREATE TABLE IF NOT EXISTS raw_events (
    raw_event_id TEXT PRIMARY KEY,

    trace_id TEXT NOT NULL
        REFERENCES events(trace_id)
        ON DELETE CASCADE,

    raw_hash TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    raw_size BIGINT NOT NULL,
    raw_path TEXT NOT NULL,

    source TEXT,

    received_time TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raw_events_trace_id
    ON raw_events(trace_id);

CREATE INDEX IF NOT EXISTS idx_raw_events_sha256
    ON raw_events(sha256);


CREATE TABLE IF NOT EXISTS lineage (
    id BIGSERIAL PRIMARY KEY,

    trace_id TEXT NOT NULL
        REFERENCES events(trace_id)
        ON DELETE CASCADE,

    normalized_field TEXT NOT NULL,
    normalized_value JSONB,

    original_field TEXT,
    original_value JSONB,

    mapping_rule TEXT,
    extraction_method TEXT,
    confidence DOUBLE PRECISION,

    parser TEXT,
    raw_hash TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lineage_trace_id
    ON lineage(trace_id);

CREATE INDEX IF NOT EXISTS idx_lineage_normalized_field
    ON lineage(normalized_field);


CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,

    trace_id TEXT,

    rule_id TEXT NOT NULL,

    severity INTEGER NOT NULL,

    title TEXT NOT NULL,
    description TEXT,

    source_ip TEXT,
    destination_ip TEXT,

    status TEXT NOT NULL DEFAULT 'open',

    alert_json JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_trace_id
    ON alerts(trace_id);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts(status);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts(created_at);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts(severity);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity_label TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);

-- Correlation cases are first-class durable records.  The deterministic
-- correlation_id makes retries and process restarts idempotent.
CREATE TABLE IF NOT EXISTS correlation_cases (
    correlation_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    case_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    risk_score INTEGER,
    source_ip TEXT,
    username TEXT,
    event_count INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    trace_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    case_json JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_correlation_cases_last_seen
    ON correlation_cases(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_correlation_cases_status
    ON correlation_cases(status);

-- Agent replay/idempotency ledger.  It is small and append-only in normal
-- operation; a duplicate batch item is safely ignored.
CREATE TABLE IF NOT EXISTS agent_receipts (
    receipt_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_agent_receipts_agent
    ON agent_receipts(agent_id, received_at DESC);

INSERT INTO schema_migrations(version)
VALUES ('2026-09-11-hardening-v1')
ON CONFLICT (version) DO NOTHING;


CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,

    name TEXT,

    hostname TEXT,

    os_name TEXT,
    os_version TEXT,

    agent_version TEXT,

    status TEXT,

    last_seen TIMESTAMPTZ,

    capabilities JSONB,
    config JSONB,
    metadata JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_status
    ON agents(status);

CREATE INDEX IF NOT EXISTS idx_agents_last_seen
    ON agents(last_seen);


CREATE TABLE IF NOT EXISTS plugin_registry (
    plugin_id TEXT PRIMARY KEY,

    name TEXT NOT NULL,

    vendor TEXT,
    product TEXT,

    version TEXT,

    format TEXT,

    status TEXT,

    parser TEXT,

    manifest JSONB,

    installed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plugins_status
    ON plugin_registry(status);

CREATE INDEX IF NOT EXISTS idx_plugins_vendor
    ON plugin_registry(vendor);

CREATE INDEX IF NOT EXISTS idx_plugins_product
    ON plugin_registry(product);