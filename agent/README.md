# ULPF Agent Plugin

The ULPF Agent is a local, air-gapped collector. It performs host/source discovery locally, buffers events in SQLite, registers with a ULPF gateway, and forwards telemetry only to the configured gateway.

## Offline / air-gapped guarantee

- No cloud APIs, telemetry SaaS, DNS discovery, internet scanning, package downloads, or external model calls.
- Discovery uses only Python standard-library APIs plus local OS commands (`journalctl`, PowerShell/Get-WinEvent) when available.
- The gateway may be an RFC1918/private-network address or localhost. An air-gapped deployment can use `https://` with an internal CA/mTLS.
- AI onboarding is not part of the collector; any future AI component must be local/on-premise to preserve the air-gap boundary.

## Phase 2: discovery

Run a local-only scan:

```bash
python agent.py discover
```

The command prints OS, architecture, hostname, local interfaces, detected log sources and capabilities. It does **not** contact the ULPF gateway.

## Phase 3: configuration

The web console provides an **Agent Setup** wizard that generates a local agent configuration. The wizard never sends credentials to a cloud service. The generated configuration can be copied to the installed agent and the service can then register with the selected ULPF gateway.
