#!/usr/bin/env python3
"""
AI Agent Audit Trail Generator

A HIPAA-compliant audit trail and compliance reporting system for AI agents
operating in healthcare networks.

HIPAA grounding:
  §164.312(a) — Access Control: agent identity registry and RBAC enforcement
  §164.312(b) — Audit Controls: tamper-evident append-only action log
  §164.312(c) — Integrity: SHA-256 input/output hashing for all PHI operations
  §164.312(d) — Authentication: delegation chain and credential management
  §164.312(e) — Transmission Security: encryption enforcement and FIPS validation
  §164.502(b) — Minimum Necessary: operation-level scope enforcement
  NIST AI RMF — Govern, Map, Measure, Manage functions
  ONC HTI-1   — AI Transparency (FAVES principles)
  FDA 2025    — ALCOA+, GMLP, PCCP guidance

Quick start::

    from agent_audit import AuditStore, ActionIngester, ComplianceEngine, ViolationDetector

    store = AuditStore(db_path="data/audit.db")
    ingester = ActionIngester()
    engine = ComplianceEngine(store)
    detector = ViolationDetector(store)

    action = ingester.ingest_action({...})
    store.store_action(action)
    violations = detector.analyze_action(action)
    for v in violations:
        store.store_violation(v)

    results = engine.assess_all_controls("2026-01-01", "2026-04-07")
    score = engine.compute_compliance_score(results)
    print(f"Compliance score: {score:.1f}/100")
"""

from .models import (
    AgentIdentity,
    AgentAction,
    ComplianceControl,
    ViolationRecord,
    ComplianceReport,
    AGENT_TYPES,
    VIOLATION_TYPES,
)
from .ingestion import ActionIngester
from .storage import AuditStore
from .compliance import ComplianceEngine, HIPAA_CONTROLS
from .violations import ViolationDetector, DETECTION_RULES
from .reporting import ReportGenerator

__all__ = [
    # Data models
    "AgentIdentity",
    "AgentAction",
    "ComplianceControl",
    "ViolationRecord",
    "ComplianceReport",
    # Vocabularies
    "AGENT_TYPES",
    "VIOLATION_TYPES",
    # Core engines
    "ActionIngester",
    "AuditStore",
    "ComplianceEngine",
    "ViolationDetector",
    "ReportGenerator",
    # Rule libraries
    "HIPAA_CONTROLS",
    "DETECTION_RULES",
]

__version__ = "1.0.0"
__author__ = "AI Agent Audit Trail Generator"
__hipaa_version__ = "2025 Security Rule Amendments"
__nist_ai_rmf_version__ = "1.0"
