-- Reserved for post-release hardening migrations.  Keep migrations
-- independently rerunnable; the Database initializer records each filename.
ALTER TABLE events ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
DELETE FROM events a USING events b
WHERE a.event_id IS NOT NULL AND a.event_id <> ''
  AND a.event_id = b.event_id AND a.ctid > b.ctid;
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_idempotency_key
    ON events(idempotency_key)
    WHERE idempotency_key IS NOT NULL AND idempotency_key <> '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_event_id
    ON events(event_id)
    WHERE event_id IS NOT NULL AND event_id <> '';
