"""Unit tests: enrichers (geo, threat intel, classification)."""
from ulpf.enricher import GeoEnricher, ThreatIntelEnricher, ClassifierEnricher, build_enrichers


def test_geo_lookup():
    geo = GeoEnricher("configs/enrichment/geo_ranges.csv")
    hit = geo.lookup("203.0.113.77")
    assert hit and hit["country"] == "US"
    miss = geo.lookup("192.168.1.50")
    assert miss is None or miss.get("country") in (None, "")


def test_geo_disabled_when_missing_file():
    geo = GeoEnricher("does/not/exist.csv")
    assert geo.lookup("8.8.8.8") is None


def test_threat_intel():
    ti = ThreatIntelEnricher("configs/enrichment/threat_intel.csv")
    hits = ti.lookup("198.51.100.23")
    assert hits, "expected 198.51.100.23 to be listed as malicious"
    assert hits[0]["type"] in ("ip", "ipv4")
    assert ti.lookup("192.168.1.50") == []


def test_threat_intel_missing_file():
    ti = ThreatIntelEnricher("does/not/exist.csv")
    assert ti.lookup("1.2.3.4") == []


def test_classifier():
    clf = ClassifierEnricher()
    assert clf.classify("Failed password for invalid user") == "authentication"
    assert clf.classify("Port scan detected") == "network"
    assert clf.classify("Payment gateway timeout") == "application"


def test_build_enrichers_from_config():
    enrichers = build_enrichers({"enrichment": {"geo": {"enabled": True},
                                                "threat_intel": {"enabled": True}}})
    assert any(isinstance(e, GeoEnricher) for e in enrichers)
    assert any(isinstance(e, ThreatIntelEnricher) for e in enrichers)


def test_build_enrichers_disabled():
    enrichers = build_enrichers({"enrichment": {"geo": {"enabled": False},
                                                "threat_intel": {"enabled": False}}})
    assert not any(isinstance(e, GeoEnricher) for e in enrichers)
    assert not any(isinstance(e, ThreatIntelEnricher) for e in enrichers)
