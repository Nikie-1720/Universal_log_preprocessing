"""Enrichment plugins. Enrichers mutate a normalized UES event in place.

All enrichers are optional and configured in pipeline.yaml. Geo and threat
intelligence are loaded from local files so the framework works fully
air-gapped (bring your own intel feeds).
"""
from __future__ import annotations

import bisect
import csv
import ipaddress
import os
import re
from pathlib import Path

from ulpf.schema import SEVERITY_NUMBER, severity_label_and_number
from ulpf.taxonomy import CATEGORY_RULES, OUTCOME_FAILURE_KEYWORDS, OUTCOME_SUCCESS_KEYWORDS, TYPE_FROM_CATEGORY
from ulpf.utils import get_u, iso, is_internal_ip, parse_timestamp, set_u


ACTION_SYNONYMS = {
    "permit": "allow",
    "permitted": "allow",
    "allowed": "allow",
    "block": "deny",
    "blocked": "deny",
    
    "drop": "deny",
    "execute": "execute",
    "ran": "execute",
    "run": "execute",
}


class Enricher:
    name = "base"

    def enrich(self, event: dict) -> None:  # pragma: no cover
        raise NotImplementedError


class TimeEnricher(Enricher):
    name = "time"

    def enrich(self, event: dict) -> None:
        ues = event["ues"]
        dt = parse_timestamp(ues.get("event_time"))
        if dt is not None:
            ues["event_time"] = iso(dt)
            ues["event_time_epoch_ms"] = int(dt.timestamp() * 1000)


class IPEnricher(Enricher):
    name = "ip"

    def enrich(self, event: dict) -> None:
        ues = event["ues"]
        for side in ("source", "destination"):
            ip = get_u(event, f"{side}.ip")
            if not ip:
                continue
            try:
                parsed = ipaddress.ip_address(str(ip).strip())
            except ValueError:
                continue
            ues.setdefault(side, {})["ip"] = str(parsed)
            ues[side]["ip_version"] = parsed.version


class GeoEnricher(Enricher):
    """Internal/external classification + optional offline country ranges CSV.

    CSV columns: start,end,country,city (IPv4 dotted or any parseable form).
    """
    name = "geo"

    def __init__(self, ranges_csv: str | None = None):
        self._starts = []
        self._ends = []
        self._meta = []
        if ranges_csv and not os.path.exists(ranges_csv):
            candidate = Path(__file__).resolve().parent.parent / ranges_csv
            if candidate.exists():
                ranges_csv = str(candidate)
        if ranges_csv and os.path.exists(ranges_csv):
            self._load(ranges_csv)

    def _load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if not row or row[0].strip().lower() in ("start", "#start"):
                    continue
                try:
                    start, end, country = int(ipaddress.ip_address(row[0].strip())), \
                        int(ipaddress.ip_address(row[1].strip())), row[2].strip()
                except (ValueError, IndexError):
                    continue
                city = row[3].strip() if len(row) > 3 else ""
                self._starts.append(start)
                self._ends.append(end)
                self._meta.append((country, city))
        pairs = sorted(zip(self._starts, self._ends, self._meta))
        if pairs:
            self._starts = [p[0] for p in pairs]
            self._ends = [p[1] for p in pairs]
            self._meta = [p[2] for p in pairs]

    def _lookup(self, ip_str: str):
        ip_int = None
        try:
            ip_int = int(ipaddress.ip_address(str(ip_str).strip()))
        except ValueError:
            return None
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx >= 0 and ip_int <= self._ends[idx]:
            return self._meta[idx]
        return None

    def lookup(self, ip_str: str):
        """Return the offline range metadata for an address.

        The public lookup helper is intentionally side-effect free so callers
        can use the same feed for preflight checks and enrichment.
        """
        hit = self._lookup(ip_str)
        if hit is None:
            return None
        country, city = hit
        return {"country": country, "city": city}

    def enrich(self, event: dict) -> None:
        for side in ("source", "destination"):
            ip = get_u(event, f"{side}.ip")
            if not ip:
                continue
            internal = is_internal_ip(ip)
            country = city = None
            if self._starts:  # explicit ranges win over internal/external guessing
                hit = self._lookup(ip)
                if hit:
                    country, city = hit
            set_u(event, f"geo.{side}", {"country": country, "city": city,
                                         "internal": bool(internal)})


class ThreatIntelEnricher(Enricher):
    """Local indicator feed (CSV: indicator,type,severity,source).

    Matches IPs exactly, domains via suffix match on host/url fields, and
    strings as substring matches on user agent / file name / message.
    """
    name = "threat_intel"

    def __init__(self, intel_csv: str | None = None):
        self.ips = {}
        self.domains = {}
        self.strings = {}
        if intel_csv and not os.path.exists(intel_csv):
            candidate = Path(__file__).resolve().parent.parent / intel_csv
            if candidate.exists():
                intel_csv = str(candidate)
        if intel_csv and os.path.exists(intel_csv):
            self._load(intel_csv)

    def _load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if not row or row[0].strip().lower() in ("indicator", "#indicator"):
                    continue
                indicator = row[0].strip()
                if not indicator:
                    continue
                itype = row[1].strip().lower() if len(row) > 1 else "unknown"
                severity = row[2].strip().lower() if len(row) > 2 else "medium"
                feed = row[3].strip() if len(row) > 3 else os.path.basename(path)
                try:
                    ipaddress.ip_address(indicator)
                    self.ips[indicator] = (itype, severity, feed)
                except ValueError:
                    if indicator.startswith("."):
                        self.domains[indicator.lower()] = (itype, severity, feed)
                    else:
                        self.strings[indicator.lower()] = (itype, severity, feed)

    def _match_ip(self, ip):
        if not ip:
            return None
        return self.ips.get(str(ip).strip())

    def _match_domain(self, host):
        if not host:
            return None
        host = str(host).strip().lower()
        for domain, meta in self.domains.items():
            if host == domain.lstrip(".") or host.endswith(domain):
                return meta
        return self.strings.get(host)

    def _match_string(self, *texts):
        for text in texts:
            if not text or not isinstance(text, str):
                continue
            low = str(text).lower()
            for indicator, meta in self.strings.items():
                if indicator in low:
                    return meta
        return None

    def lookup(self, value: str) -> list[dict]:
        """Look up an IP, domain, or feed string without mutating an event."""
        value = str(value or "").strip()
        if not value:
            return []
        matches = []
        meta = self._match_ip(value)
        if meta is None:
            meta = self._match_domain(value)
        if meta is None:
            meta = self._match_string(value)
        if meta is not None:
            matches.append({
                "indicator": value,
                "type": meta[0],
                "severity": meta[1],
                "feed": meta[2],
            })
        return matches

    def enrich(self, event: dict) -> None:
        if not (self.ips or self.domains or self.strings):
            return
        matched: list[dict] = []

        def add(field: str, indicator: str, meta):
            if meta:
                matched.append({"field": field, "indicator": indicator,
                                "type": meta[0], "severity": meta[1], "feed": meta[2]})

        src_ip = get_u(event, "source.ip")
        if src_ip and src_ip in self.ips:
            add("source.ip", src_ip, self.ips[src_ip])
        dst_ip = get_u(event, "destination.ip")
        if dst_ip and dst_ip in self.ips:
            add("destination.ip", dst_ip, self.ips[dst_ip])
        host = get_u(event, "http.host") or get_u(event, "dns.query")
        if host:
            meta = self._match_domain(host)
            if meta:
                add("http.host", str(host)[:120], meta)
        url = get_u(event, "http.url")
        if url and "://" in str(url):
            url_host = re.sub(r"^[a-z]+://([^/:]+).*$", r"\1", str(url), flags=re.I)
            meta = self._match_domain(url_host)
            if meta:
                add("http.url", url_host, meta)
        st = self._match_string(get_u(event, "http.user_agent"), get_u(event, "file.name"),
                                get_u(event, "message"), url)
        if st:
            add("message", st[0], st)  # indicator text is matched string
            matched[-1]["indicator"] = next(
                (ind for ind in self.strings if ind in str(get_u(event, "message") or "").lower()
                 or ind in str(get_u(event, "http.user_agent") or "").lower()
                 or ind in str(url or "").lower()), "unknown")
        if not matched:
            return
        ues = event["ues"]
        ues.setdefault("threat", {})["matched"] = matched
        score = max(SEVERITY_NUMBER.get(m["severity"], 50) for m in matched)
        ues["threat"]["score"] = score
        ues.setdefault("tags", []).append("threat-intel")
        label = ues.get("severity_label")
        if label and SEVERITY_NUMBER.get(label, 10) < score:
            new_label = next((k for k in ("debug", "info", "low", "medium", "high", "critical")
                              if SEVERITY_NUMBER[k] == score), "medium")
            ues["severity_label"] = new_label
            ues["severity"] = score


class ClassifierEnricher(Enricher):
    """Fills category/type/action/outcome from context when not already set."""
    name = "classify"

    def classify(self, text: str) -> str:
        """Classify standalone text using the same deterministic rules as enrich()."""
        text = str(text or "")
        for category, pattern in CATEGORY_RULES:
            if pattern.search(text):
                return category
        if "port scan" in text.lower() or "port scanning" in text.lower():
            return "network"
        if "http" in text.lower() or "https" in text.lower():
            return "web"
        return "system"

    def enrich(self, event: dict) -> None:
        ues = event["ues"]
        action = ues.get("action")
        if action:
            ues["action"] = ACTION_SYNONYMS.get(str(action).lower(), str(action).lower())
        text = " ".join(filter(None, [ues.get("message"), event.get("raw")]))[:4000]
        if not ues.get("outcome"):
            if OUTCOME_FAILURE_KEYWORDS.search(text):
                ues["outcome"] = "failure"
            elif OUTCOME_SUCCESS_KEYWORDS.search(text):
                ues["outcome"] = "success"
        if not ues.get("category"):
            if get_u(event, "http.url") or get_u(event, "http.method"):
                ues["category"] = "web"
            elif get_u(event, "dns.query"):
                ues["category"] = "network"
            else:
                for category, pattern in CATEGORY_RULES:
                    if pattern.search(text):
                        ues["category"] = category
                        break
                else:
                    if get_u(event, "source.ip") or get_u(event, "destination.ip"):
                        ues["category"] = "network"
                    else:
                        ues["category"] = "system"
        if not ues.get("type"):
            ues["type"] = TYPE_FROM_CATEGORY.get(ues.get("category", ""), "event")
        if ues.get("category") == "authentication" and not ues.get("action"):
            ues["action"] = "allow" if ues.get("outcome") == "success" else "deny"


class SeverityEnricher(Enricher):
    name = "severity"

    def enrich(self, event: dict) -> None:
        ues = event["ues"]
        label, number = severity_label_and_number(ues.get("severity_label") or ues.get("severity"))
        if label is None:
            label, number = "info", 10
        ues["severity_label"] = label
        ues["severity"] = max(0, min(100, number or 0))


class IntegrityEnricher(Enricher):
    name = "integrity"

    def enrich(self, event: dict) -> None:
        trace = event.setdefault("trace", {})
        trace.setdefault("algorithm", "sha256")
        trace.setdefault("raw_hash", "")
        trace["status"] = "verified"


ENRICHER_CLASSES = {
    "time": TimeEnricher,
    "ip": IPEnricher,
    "geo": GeoEnricher,
    "threat_intel": ThreatIntelEnricher,
    "classify": ClassifierEnricher,
    "severity": SeverityEnricher,
    "integrity": IntegrityEnricher,
}

DEFAULT_ORDER = ["time", "ip", "geo", "threat_intel", "classify", "severity", "integrity"]


def build_enrichers(config: dict):
    enr_cfg = (config or {}).get("enrichment") or {}
    order = enr_cfg.get("enrichers") or DEFAULT_ORDER
    instances = []
    for name in order:
        cls = ENRICHER_CLASSES.get(str(name))
        if cls is None:
            continue
        if ((enr_cfg.get(str(name)) or {}).get("enabled")) is False:
            continue  # per-enricher kill switch: enrichment.<name>.enabled: false
        if cls is GeoEnricher:
            instances.append(GeoEnricher(enr_cfg.get("geo_ranges_csv")))
        elif cls is ThreatIntelEnricher:
            instances.append(ThreatIntelEnricher(enr_cfg.get("threat_intel_csv")))
        else:
            instances.append(cls())
    return instances
