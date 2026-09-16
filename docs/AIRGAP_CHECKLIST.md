# Air-Gap Acceptance Checklist

- [x] Core parsing/normalization has no mandatory third-party runtime dependency.
- [x] Agent uses Python standard library only.
- [x] Agent does not perform Internet discovery.
- [x] Unknown-log onboarding works with deterministic local mapping.
- [x] Optional model integration is local-only and opt-in.
- [x] Raw event SHA-256 is retained for forensic integrity.
- [x] Agent local spool survives temporary gateway outages.
- [x] File offsets are checkpointed atomically.
- [x] HTTPS/private CA and optional mTLS are supported.
- [x] Agent/operator bearer authentication is supported.
- [x] API request bodies are bounded.
- [x] `/api/live` and `/api/ready` are available for health checks.
- [x] Static air-gap preflight script is included.
- [x] Local benchmark is included.
- [x] No cloud service is required for the deterministic demo path.

Before a real deployment, security teams should replace development/trusted-network
defaults with their private CA, tokens, filesystem ACLs and host firewall policy.
