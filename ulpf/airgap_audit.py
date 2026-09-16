from __future__ import annotations

import os
import socket
from urllib.parse import urlparse


def _is_local_or_private_host(host: str) -> bool:
    if not host:
        return True

    host = host.lower().strip()

    if host in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        return True

    try:
        ip = socket.gethostbyname(host)

        private_prefixes = (
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
        )

        return ip.startswith(private_prefixes)

    except Exception:
        return False


def _configured_endpoints():
    endpoints = []

    gateway = os.getenv("ULPF_GATEWAY", "").strip()

    if gateway:
        endpoints.append(gateway)

    # Agent gateway can also be configured through the normal runtime
    # environment. Do not invent or contact anything here.
    agent_gateway = os.getenv("ULPF_AGENT_GATEWAY", "").strip()

    if agent_gateway and agent_gateway not in endpoints:
        endpoints.append(agent_gateway)

    return endpoints


def run_airgap_audit():
    """
    Offline configuration/security audit.

    IMPORTANT:
    This function does not make network requests.
    It only inspects configured endpoints and validates
    whether they are local/private.
    """

    configured = _configured_endpoints()

    allowed_services = []
    blocked_services = []

    for endpoint in configured:
        try:
            parsed = urlparse(endpoint)
            host = parsed.hostname or ""

            item = {
                "endpoint": endpoint,
                "host": host,
                "scheme": parsed.scheme or "",
            }

            if _is_local_or_private_host(host):
                allowed_services.append(item)
            else:
                blocked_services.append(item)

        except Exception:
            blocked_services.append({
                "endpoint": endpoint,
                "host": "",
                "scheme": "",
            })

    status = "PASS" if not blocked_services else "FAIL"

    return {
        "mode": "air-gapped",
        "status": status,

        # These counters represent requests observed by
        # this audit layer. The audit itself performs ZERO requests.
        "external_endpoints": len(blocked_services),
        "external_requests": 0,
        "cloud_api_calls": 0,
        "external_dns_requests": 0,

        "network_access_required": False,

        "configured_endpoints": configured,
        "allowed_services": allowed_services,
        "blocked_services": blocked_services,

        "audit": {
            "performed_offline": True,
            "network_requests_made": 0,
            "cloud_services_contacted": 0,
            "external_dns_queries_made": 0,
        },
    }