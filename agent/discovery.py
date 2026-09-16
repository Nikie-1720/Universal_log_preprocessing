"""Dependency-free local host/source discovery for the ULPF Agent.

This module is intentionally air-gap safe: it performs only local OS/filesystem
inspection and never contacts the network, cloud services, package managers,
or telemetry endpoints.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path


WINDOWS_EVENT_CHANNELS = [
    "System",
    "Application",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
]

LINUX_FILE_CANDIDATES = [
    ("syslog", "/var/log/syslog"),
    ("messages", "/var/log/messages"),
    ("auth", "/var/log/auth.log"),
    ("secure", "/var/log/secure"),
    ("audit", "/var/log/audit/audit.log"),
    ("kern", "/var/log/kern.log"),
]

APP_DIR_CANDIDATES = [
    ("nginx", "/var/log/nginx"),
    ("apache", "/var/log/apache2"),
    ("httpd", "/var/log/httpd"),
]


def _run(command, timeout=3):
    try:
        return subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _network_interfaces():
    """Return interface names/IPs using only the local stdlib APIs."""
    result = []
    names = []
    try:
        if hasattr(socket, "if_nameindex"):
            names = [name for _, name in socket.if_nameindex()]
    except OSError:
        names = []

    if not names:
        names = ["default"]

    for name in names:
        ips = []
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                addr = info[4][0]
                if addr not in ips:
                    ips.append(addr)
        except OSError:
            pass
        result.append({"name": name, "addresses": ips})
    return result


def _windows_channels():
    found = []
    if shutil.which("powershell") is None and shutil.which("pwsh") is None:
        return found
    exe = shutil.which("powershell") or shutil.which("pwsh")
    for channel in WINDOWS_EVENT_CHANNELS:
        escaped = channel.replace("'", "''")
        cmd = (
            f"Get-WinEvent -ListLogName '{escaped}' -ErrorAction SilentlyContinue "
            "| Select-Object -First 1 LogName"
        )
        if _run([exe, "-NoProfile", "-NonInteractive", "-Command", cmd]):
            found.append(channel)
    return found


def _linux_sources():
    sources = []
    for name, path in LINUX_FILE_CANDIDATES:
        p = Path(path)
        if p.is_file() and os.access(p, os.R_OK):
            sources.append({"kind": "file", "id": name, "path": str(p), "readable": True})
    if shutil.which("journalctl"):
        sources.append({"kind": "journald", "id": "systemd-journal", "available": True})
    for name, path in APP_DIR_CANDIDATES:
        p = Path(path)
        if p.is_dir() and os.access(p, os.R_OK):
            sources.append({"kind": "directory", "id": name, "path": str(p), "pattern": "*.log", "readable": True})
    return sources


def discover(custom_paths=None):
    """Build a deterministic local capability report."""
    system = platform.system().lower()
    os_name = platform.platform()
    arch = platform.machine() or "unknown"
    hostname = platform.node() or socket.gethostname() or "unknown"
    report = {
        "schema_version": "ulpf-discovery-v1",
        "offline": True,
        "network_access_required": False,
        "system": {
            "os": system,
            "platform": os_name,
            "architecture": arch,
            "hostname": hostname,
            "python": platform.python_version(),
        },
        "network_interfaces": _network_interfaces(),
        "sources": [],
        "capabilities": ["os-detection", "network-interface-discovery"],
    }

    if system == "windows":
        channels = _windows_channels()
        for ch in channels:
            report["sources"].append({"kind": "windows-eventlog", "id": ch, "channel": ch, "available": True})
        if channels:
            report["capabilities"].append("windows-eventlog")
        # Common local Windows application/IIS log roots; no network scanning.
        for raw in [os.environ.get("WINDIR", r"C:\\Windows") + r"\\System32\\LogFiles", r"C:\\inetpub\\logs\\LogFiles"]:
            p = Path(raw)
            if p.is_dir() and os.access(p, os.R_OK):
                report["sources"].append({"kind": "directory", "id": "windows-app", "path": str(p), "pattern": "*.log", "readable": True})
        report["capabilities"].extend(["local-file-collection", "directory-discovery"])
    else:
        linux = _linux_sources()
        report["sources"].extend(linux)
        kinds = {s["kind"] for s in linux}
        if "journald" in kinds:
            report["capabilities"].append("journald")
        if "file" in kinds:
            report["capabilities"].append("local-file-collection")
        if "directory" in kinds:
            report["capabilities"].append("directory-discovery")

    for raw in custom_paths or []:
        p = Path(os.path.expandvars(str(raw))).expanduser()
        if p.is_file() and os.access(p, os.R_OK):
            report["sources"].append({"kind": "file", "id": "custom", "path": str(p), "readable": True})
        elif p.is_dir() and os.access(p, os.R_OK):
            report["sources"].append({"kind": "directory", "id": "custom", "path": str(p), "pattern": "*.log", "readable": True})

    # Stable de-duplication makes the report safe for registration/UI display.
    seen = set()
    unique = []
    for source in report["sources"]:
        key = json.dumps(source, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(source)
    report["sources"] = unique
    report["capabilities"] = sorted(set(report["capabilities"]))
    return report
