# ULPF Air-Gapped Quick Start

## Option A — no Docker / no Internet

Requires Python 3.9+ on the host. The runtime core has no mandatory third-party
Python dependency.

Windows PowerShell:

```powershell
$env:ULPF_DATA_DIR = "$PWD\data-runtime"
$env:ULPF_ALLOW_UNAUTHENTICATED_AGENT = "true"
python -m ulpf.web
```

Linux:

```bash
ULPF_DATA_DIR="$PWD/data-runtime" ULPF_ALLOW_UNAUTHENTICATED_AGENT=true python -m ulpf.web
```

Open the local console on port 5173.

## Option B — private Docker network

Build/import the required images while still connected, then move the image
archives and this source bundle into the isolated network. Do not run `docker
compose pull` inside the air gap.

For PostgreSQL-backed deployments set a strong `POSTGRES_PASSWORD` in a private
`.env` file. For a completely self-contained demo, use the local fallback profile
above.

## Agent

Run local discovery first:

```bash
python agent/agent.py discover
```

Then install the plugin using the OS-specific installer. Point `gateway` to the
private ULPF address. For production use, configure `ULPF_AGENT_TOKEN` and HTTPS
or mTLS.

## Local AI

The deterministic onboarding mapper works without a model. Optional Ollama is
local-only and must be explicitly enabled with `ULPF_LOCAL_AI=true`.
