# 2-minute judge demo

## 0:00 — Problem
"Network devices produce different log formats and field names. ULPF creates a common
preprocessing layer without throwing away the original evidence."

## 0:20 — Ingest
Load the FortiGate sample in the console and click **Normalize events**.

Point at:
- source.ip
- destination.ip
- destination.port
- event.action

## 0:45 — Forensic USP
Click `destination.port`.

Show:
- original field = `dstport`
- original value = `443`
- mapping = `dstport -> destination.port`
- extraction method
- confidence = 100%
- parser version
- raw SHA-256
- exact raw event

Say:
"Instead of asking the analyst to trust a normalized value, ULPF exposes its lineage."

## 1:05 — Plugin Contract
Open `plugins/` and show the contract:
manifest + parser + mappings + tests.

Say:
"A new vendor can onboard through the contract without changing the ULPF core."

## 1:20 — Air-gap
Show Docker Compose.

Say:
"The core and console use standard-library Python and local storage. No cloud API is
required for the deterministic processing path."

## 1:35 — Don't Replace, Augment
Explain:
"ULPF outputs a universal event that can be adapted for ECS, Splunk CIM or a custom
schema and fed into an existing SIEM or data lake."

## 1:50 — Close
"Unknown sources can be analyzed offline, approved by an operator and turned into a
deterministic plugin. AI accelerates onboarding; it does not become a mandatory
dependency for every production event."
