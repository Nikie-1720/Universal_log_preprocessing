# ULPF Agent Plugin

This directory contains the packaging/install entry points for the ULPF Collector Agent.

## Windows source installer

From PowerShell on a Windows host:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install-ulpf-agent-windows.ps1 -Gateway "http://ULPF-SERVER:5173"
```

The installer:

1. Detects Windows and CPU architecture.
2. Locates Python 3.9+ for the current source-build workflow.
3. Installs the agent under `Program Files\ULPF-Agent`.
4. Stores mutable configuration/state under `ProgramData\ULPF-Agent`.
5. Creates and starts the `ULPFAgent` Windows service.
6. Writes an installation manifest for later upgrade/uninstall tooling.

The production release will bundle the Python runtime so the downloaded plugin has no Python prerequisite. The same installer contract will be retained.

## Linux source installer

```bash
ULPF_GATEWAY="http://ULPF-SERVER:5173" sudo -E ./scripts/install-ulpf-agent-linux.sh
```

The installer creates a systemd service and keeps mutable state under `/var/lib/ulpf-agent`.

## Design boundary

The Agent only collects, buffers, registers, heartbeats, and forwards raw events. Parsing, normalization, lineage, correlation, and storage remain in the central ULPF platform.
