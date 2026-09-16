# Phase 2 + Phase 3 — Agent Discovery & Configuration

## Air-gap design rule

The agent and setup workflow are designed for disconnected/private networks. No cloud API, DNS-based discovery, external model, telemetry SaaS, package registry, or internet call is required.

### Phase 2 — Local discovery

`agent/discovery.py` performs only local inspection:

- OS / architecture / hostname / Python runtime
- local network interface names and addresses available through standard-library APIs
- Windows Event Log channels using local PowerShell/Get-WinEvent
- Linux syslog/auth/audit files when readable
- systemd journal availability via local `journalctl`
- common local Nginx/Apache/HTTPD log directories
- configured custom files/directories

Run:

```bash
python agent/agent.py discover
```

This command never contacts the ULPF gateway.

The registration payload now includes `discovery` plus capabilities and detected sources so the ULPF console can show what the endpoint can collect.

## Phase 3 — Configuration wizard

The **Agents** page in the local ULPF web console provides:

1. target OS selection
2. agent name
3. private ULPF gateway
4. optional agent token
5. local source selection
6. Agent Plugin download
7. local `agent.yaml` generation/copy
8. registered-agent health view

The generated configuration is produced in the browser and is not sent to a cloud service.

### Deployment boundary

The current source installer expects Python 3.9+ on the target host. A future release can bundle a Python runtime into a native Windows/Linux executable installer; the architecture does not depend on internet connectivity.
