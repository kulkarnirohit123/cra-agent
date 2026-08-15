"""Smoke tests for core data models."""

from __future__ import annotations

from src.core.models import Finding, Severity, TriagedFinding


def test_severity_ordering() -> None:
    assert Severity.CRITICAL >= Severity.HIGH
    assert Severity.HIGH >= Severity.MEDIUM
    assert not (Severity.LOW >= Severity.MEDIUM)


def test_severity_weight() -> None:
    assert Severity.CRITICAL.weight > Severity.INFO.weight


def test_finding_generate_id_is_deterministic() -> None:
    id_a = Finding.generate_id("secrets", "CWE-798", "src/app.py", 2, "abc123def456")
    id_b = Finding.generate_id("secrets", "CWE-798", "src/app.py", 2, "abc123def456")
    assert id_a == id_b


def test_finding_generate_id_differs_by_input() -> None:
    id_a = Finding.generate_id("secrets", "CWE-798", "src/app.py", 2, "abc123def456")
    id_b = Finding.generate_id("secrets", "CWE-798", "src/app.py", 3, "abc123def456")
    assert id_a != id_b


def test_finding_is_critical(sample_finding: Finding) -> None:
    assert sample_finding.is_critical is True


def test_triaged_finding_roundtrip(sample_triaged_finding: TriagedFinding) -> None:
    assert sample_triaged_finding.triage.confidence == 0.9
    assert sample_triaged_finding.severity == Severity.HIGH
