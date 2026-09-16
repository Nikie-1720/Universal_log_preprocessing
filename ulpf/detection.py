
"""Heuristic raw-log format detection (used for auto-routing and fallbacks)."""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from io import StringIO


# ---------------------------------------------------------------------------
# Format detection patterns
# ---------------------------------------------------------------------------

RE_CEF = re.compile(r"^CEF:\d+\|")

RE_LEEF = re.compile(r"^LEEF:\d+\.\d+\|")

RE_SYSLOG_RFC3164 = re.compile(
    r"^(?:<\d{1,3}>)?\s*[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s"
)

RE_SYSLOG_RFC5424 = re.compile(
    r"^<\d{1,3}>\d\s+\S+\s+\S+"
)

RE_KV_PAIR = re.compile(
    r'(?<![\w])([A-Za-z_][\w.\-]*)\s*=\s*(?:"[^"]*"|[^\s,;]+)'
)

RE_XML = re.compile(r"^\s*<[\w?!]")


# ---------------------------------------------------------------------------
# CSV detection helper
# ---------------------------------------------------------------------------

def _looks_like_csv(line: str) -> bool:
    """
    Determine whether the supplied raw text has a valid CSV-like structure.

    CSV detection is deliberately conservative so ordinary text containing
    commas is not incorrectly classified as CSV.

    Requirements:
    - At least two non-empty rows.
    - Every row has the same number of columns.
    - At least two columns.
    - CSV parser must be able to parse the input successfully.
    """

    if "," not in line:
        return False

    try:
        rows = list(csv.reader(StringIO(line)))
    except (csv.Error, ValueError):
        return False

    # Remove completely empty rows.
    non_empty_rows = [
        row for row in rows
        if any(cell.strip() for cell in row)
    ]

    if len(non_empty_rows) < 2:
        return False

    # All rows should have the same column count.
    widths = {len(row) for row in non_empty_rows}

    if len(widths) != 1:
        return False

    column_count = next(iter(widths))

    # A CSV record should contain at least two columns.
    if column_count < 2:
        return False

    return True


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_format(raw: str) -> dict:
    """
    Return:
        {
            "format": str,
            "confidence": float,
            "reason": str
        }

    Detection order is intentional:
        JSON
        CEF
        LEEF
        Syslog RFC5424
        Syslog RFC3164
        Cisco ASA/FTD/PIX text
        XML
        key=value
        CSV
        free text
    """

    if not isinstance(raw, str):
        return {
            "format": "text",
            "confidence": 0.0,
            "reason": "raw input is not a string",
        }

    line = raw.strip()

    if not line:
        return {
            "format": "empty",
            "confidence": 0.0,
            "reason": "blank line",
        }

    # -----------------------------------------------------------------------
    # JSON
    # -----------------------------------------------------------------------

    if line.startswith("{") or line.startswith("["):
        try:
            obj = json.loads(line)

            if isinstance(obj, (dict, list)):
                return {
                    "format": "json",
                    "confidence": 0.95,
                    "reason": "valid JSON document",
                }

        except (ValueError, TypeError):
            pass

    # -----------------------------------------------------------------------
    # CEF
    # -----------------------------------------------------------------------

    if RE_CEF.match(line):
        return {
            "format": "cef",
            "confidence": 0.98,
            "reason": "CEF header",
        }

    # -----------------------------------------------------------------------
    # LEEF
    # -----------------------------------------------------------------------

    if RE_LEEF.match(line):
        return {
            "format": "leef",
            "confidence": 0.98,
            "reason": "LEEF header",
        }

    # -----------------------------------------------------------------------
    # Syslog RFC5424
    # -----------------------------------------------------------------------

    if RE_SYSLOG_RFC5424.match(line):
        return {
            "format": "syslog",
            "confidence": 0.92,
            "reason": "RFC5424 structured syslog",
        }

    # -----------------------------------------------------------------------
    # Syslog RFC3164
    # -----------------------------------------------------------------------

    if RE_SYSLOG_RFC3164.match(line):
        return {
            "format": "syslog",
            "confidence": 0.85,
            "reason": "RFC3164 bsd syslog",
        }

    # -----------------------------------------------------------------------
    # Cisco ASA / FTD / PIX
    # -----------------------------------------------------------------------

    if re.match(r"^%(?:ASA|FTD|PIX)-\d+-\d+:", line):
        return {
            "format": "text",
            "confidence": 0.4,
            "reason": "Cisco ASA-style message (vendor parser recommended)",
        }

    # -----------------------------------------------------------------------
    # XML
    # -----------------------------------------------------------------------

    if RE_XML.match(line):
        try:
            ET.fromstring(line)

            return {
                "format": "xml",
                "confidence": 0.9,
                "reason": "well-formed XML",
            }

        except ET.ParseError:
            pass

    # -----------------------------------------------------------------------
    # Key=value
    # -----------------------------------------------------------------------

    pairs = len(RE_KV_PAIR.findall(line))

    if pairs >= 3:
        return {
            "format": "kv",
            "confidence": min(0.9, 0.6 + pairs * 0.02),
            "reason": f"{pairs} key=value pairs",
        }

    # -----------------------------------------------------------------------
    # CSV
    #
    # IMPORTANT:
    # Do this AFTER KV detection.
    #
    # Example:
    #   timestamp,src_ip,action
    #   2026-02-14,10.0.0.5,deny
    #
    # is correctly detected as CSV.
    #
    # Ordinary text such as:
    #   "Login failed, please investigate"
    #
    # is not detected as CSV because it has only one parsed column.
    # -----------------------------------------------------------------------

    if _looks_like_csv(line):
        return {
            "format": "csv",
            "confidence": 0.85,
            "reason": "consistent comma-separated columns",
        }

    # -----------------------------------------------------------------------
    # Free text fallback
    # -----------------------------------------------------------------------

    return {
        "format": "text",
        "confidence": 0.2,
        "reason": "free text",
    }

