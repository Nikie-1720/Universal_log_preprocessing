# Phase 1 — ULPF Agent Plugin

## Objective

Turn the existing ULPF collector into a distributable, service-oriented agent plugin without changing the central ULPF parsing/normalization pipeline.

## What is implemented

- Windows OS and CPU architecture discovery during installation.
- Linux OS and architecture discovery during installation.
- Source-install runtime validation for Python 3.9+.
- Windows installation under `Program Files\\ULPF-Agent`.
- Mutable Windows configuration/state under `ProgramData\\ULPF-Agent`.
- Automatic Windows Service registration and restart policy.
- Linux systemd service with persistent writable state under `/var/lib/ulpf-agent`.
- Installation manifest for upgrade/uninstall tooling.
- A plugin manifest describing capabilities and offline operation.
- Packaging scripts for a distributable `ULPF-Agent-Plugin.zip`.

## Production packaging note

The current source installer checks for Python 3.9+ because this environment cannot produce a Windows native executable. The next packaging iteration should build a bundled Windows executable with PyInstaller (or an equivalent approved bundler) so the downloaded plugin does not require Python on the target machine.

The installer contract and installation paths are intentionally stable so the runtime bundling can be added without redesigning the agent.

## Demo flow enabled by Phase 1

```text
Download ULPF-Agent-Plugin.zip
        ↓
Run Install-ULPF-Agent.cmd
        ↓
OS + architecture detected
        ↓
Agent installed
        ↓
ULPFAgent Windows service created
        ↓
Agent starts
        ↓
Agent registers/heartbeats with ULPF gateway
```

The configuration wizard and automatic source discovery UI are deliberately left for Phase 2/3. This keeps the first change isolated and testable.
