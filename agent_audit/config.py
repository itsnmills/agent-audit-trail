#!/usr/bin/env python3
"""
Configuration constants and environment variable loading for the
AI Agent Audit Trail Generator.

All thresholds are grounded in HIPAA Security Rule requirements,
NIST SP 800-66r2 guidance, and industry-standard security practices.
Override any value via environment variable for deployment customization.
"""

from __future__ import annotations

import os
from pathlib import Path

# ===========================================================================
# Database
# ===========================================================================

DB_PATH = Path(os.getenv("AUDIT_DB_PATH", "data/audit.db"))
"""
Path to the SQLite audit database.

Production deployments should use a dedicated encrypted volume.
Per 2025 HIPAA amendments, encryption at rest is now mandatory.
"""

# ===========================================================================
# Violation Detection Thresholds
# ===========================================================================

BULK_ACCESS_THRESHOLD: int = int(os.getenv("AUDIT_BULK_THRESHOLD", "100"))
"""
Number of distinct patient records accessed in a single session before
triggering V-005 (Bulk PHI Exfiltration Pattern).

Grounded in §164.502(b) Minimum Necessary: accessing >100 records
in a single session almost always exceeds what is required for any
individual clinical workflow and warrants investigation.
"""

CREDENTIAL_ROTATION_MAX_DAYS: int = int(os.getenv("AUDIT_CRED_ROTATION_DAYS", "90"))
"""
Maximum days between agent credential rotations before triggering V-007.

Aligns with NIST SP 800-63B §5.1.1 and 2025 HIPAA amendment requirements
for periodic re-authentication. 90-day rotation is the minimum standard;
critical-tier agents should rotate every 30 days.
"""

MAX_SESSION_HOURS: int = int(os.getenv("AUDIT_MAX_SESSION_HOURS", "8"))
"""
Maximum agent session duration (hours) before triggering V-012.

§164.312(a)(2)(iii) Automatic Logoff: sessions must terminate after
a defined period of inactivity or maximum duration. 8 hours aligns
with a standard clinical shift cycle.
"""

STALE_AGENT_DAYS: int = int(os.getenv("AUDIT_STALE_AGENT_DAYS", "30"))
"""
Days since last activity before an agent is considered stale (V-017).

Agents not used in 30+ days should be reviewed for decommissioning per
§164.312(a) — maintaining an accurate, minimal agent inventory reduces
attack surface.
"""

REDUNDANT_ACCESS_MINUTES: int = int(os.getenv("AUDIT_REDUNDANT_ACCESS_MINS", "5"))
"""
Window (minutes) within which re-reading the same record is flagged as
redundant (V-020). Repeated reads of the same PHI within 5 minutes with
no write may indicate a data harvesting pattern under §164.502(b).
"""

AFTER_HOURS_START: int = int(os.getenv("AUDIT_AFTER_HOURS_START", "20"))
"""Hour (0-23, local time) after which PHI access is flagged as after-hours (V-016)."""

AFTER_HOURS_END: int = int(os.getenv("AUDIT_AFTER_HOURS_END", "7"))
"""Hour (0-23, local time) before which PHI access is flagged as after-hours (V-016)."""

EXFIL_WINDOW_MINUTES: int = int(os.getenv("AUDIT_EXFIL_WINDOW_MINS", "60"))
"""Rolling window (minutes) for bulk exfiltration pattern detection."""

SCOPE_DRIFT_WINDOW_DAYS: int = int(os.getenv("AUDIT_SCOPE_DRIFT_DAYS", "30"))
"""Lookback window (days) for detecting gradual scope expansion patterns."""

# ===========================================================================
# Compliance Scoring
# ===========================================================================

REQUIRED_CONTROL_WEIGHT: float = 2.0
"""
Weight multiplier for REQUIRED implementation specifications in compliance scoring.

Per §164.306(b)(2), required specifications must be implemented — they are not
subject to the flexibility afforded to addressable specifications. This 2x weight
ensures a single uncompliant required control materially impacts the overall score.
"""

ADDRESSABLE_CONTROL_WEIGHT: float = 1.0
"""
Weight multiplier for ADDRESSABLE implementation specifications.

Addressable does not mean optional — it means the covered entity must assess
whether the specification is reasonable and appropriate given its environment.
If not implemented, an equivalent alternative measure must be documented.
"""

COMPLIANT_SCORE: float = 1.0
PARTIALLY_COMPLIANT_SCORE: float = 0.5
NON_COMPLIANT_SCORE: float = 0.0

# Compliance rating thresholds (0–100 scale)
RATING_COMPLIANT_THRESHOLD: float = 90.0
RATING_SUBSTANTIAL_THRESHOLD: float = 75.0
RATING_PARTIAL_THRESHOLD: float = 50.0
RATING_CRITICAL_THRESHOLD: float = 25.0

# ===========================================================================
# Severity Score Mapping (CVSS-inspired, 0.0–10.0)
# ===========================================================================

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 0.5,
}

# Violation severity to PHI impact score multiplier
PHI_IMPACT_MULTIPLIERS: dict[str, float] = {
    "confirmed_phi_exposure": 1.0,
    "potential_phi_exposure": 0.7,
    "no_phi_impact": 0.3,
}

# ===========================================================================
# Report Generation
# ===========================================================================

ORGANIZATION_NAME: str = os.getenv("AUDIT_ORG_NAME", "Healthcare Organization")
"""Organization name for report headers and executive summaries."""

REPORT_OUTPUT_DIR = Path(os.getenv("AUDIT_REPORT_DIR", "reports"))
"""Directory where generated PDF and Markdown reports are saved."""

REPORT_RETENTION_DAYS: int = int(os.getenv("AUDIT_REPORT_RETENTION_DAYS", "2190"))
"""
Report retention period in days (default 6 years).

§164.316(b)(2)(i) requires HIPAA documentation be retained for 6 years
from creation or from when it was last in effect, whichever is later.
"""

AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "2190"))
"""Audit log retention — same 6-year requirement as documentation."""

# ===========================================================================
# Dashboard
# ===========================================================================

DASHBOARD_HOST: str = os.getenv("AUDIT_DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT: int = int(os.getenv("AUDIT_DASHBOARD_PORT", "8090"))
DASHBOARD_RELOAD: bool = os.getenv("AUDIT_DASHBOARD_RELOAD", "false").lower() == "true"

# ===========================================================================
# Cryptographic Constants
# ===========================================================================

HASH_ALGORITHM: str = "sha256"
"""SHA-256 for all tamper-evidence hashing per NIST FIPS 180-4."""

GENESIS_HASH: str = "0" * 64
"""Sentinel hash for the first record in the audit chain (no predecessor)."""

APPROVED_ENCRYPTION_ALGORITHMS: set[str] = {
    "AES-256-GCM",
    "AES-256-CBC",
    "TLS-1.3",
    "TLS-1.2",
}
"""
Approved encryption algorithms per 2025 HIPAA amendments and NIST SP 800-111.
TLS-1.2 is included but flagged as deprecated in favor of TLS-1.3.
"""

FIPS_REQUIRED_ALGORITHMS: set[str] = {
    "AES-256-GCM",
    "AES-256-CBC",
}
"""
Algorithms that qualify as FIPS 140-3 compliant (when using a validated module).
TLS record layer alone is insufficient — the underlying cipher must be FIPS-validated.
"""

# ===========================================================================
# PHI Classification Taxonomy
# Full list of HIPAA §164.514(b)(2) 18 identifiers + clinical extensions
# ===========================================================================

PHI_CATEGORIES: set[str] = {
    # 18 HIPAA Safe Harbor identifiers
    "demographics",      # Names
    "address",           # Geographic data (street, zip, etc.)
    "dob",               # Dates (except year) related to individuals
    "phone",             # Phone numbers
    "fax",               # Fax numbers
    "email",             # Email addresses
    "ssn",               # Social Security numbers
    "mrn",               # Medical record numbers
    "account_number",    # Health plan beneficiary numbers / account numbers
    "certificate",       # Certificate/license numbers
    "device_id",         # Device identifiers and serial numbers
    "web_url",           # Web URLs
    "ip_address",        # IP addresses
    "biometric",         # Biometric identifiers (fingerprints, voice prints)
    "photo",             # Full-face photographs and comparable images
    "unique_id",         # Any unique identifying number/code not listed above
    # Clinical data categories (PHI but not in 18-identifier list)
    "diagnosis",         # ICD-10 codes, diagnoses
    "medications",       # Prescription drug data
    "lab_values",        # Laboratory results
    "vitals",            # Vital signs
    "procedures",        # CPT codes, procedures performed
    "insurance",         # Insurance/payer information
    "imaging",           # Radiology/imaging studies
    "genomics",          # Genetic/genomic data
    "mental_health",     # Behavioral health records (extra protections in many states)
    "substance_use",     # Substance use disorder records (42 CFR Part 2 protections)
    "reproductive",      # Reproductive health (post-Dobbs additional state protections)
}

NON_PHI_CLASSIFICATIONS: set[str] = {
    "de_identified",    # Meets §164.514(b) Safe Harbor or Expert Determination
    "limited_dataset",  # §164.514(e) — some identifiers stripped, DUA required
    "non_phi",          # No PHI present
}

# ===========================================================================
# Agent Operation Types
# ===========================================================================

ALLOWED_OPERATIONS: set[str] = {
    "read",
    "write",
    "query",
    "upload",
    "download",
    "delete",
    "transmit",
    "transform",
    "summarize",
    "classify",
    "authenticate",
    "search",
    "annotate",
    "generate",
    "validate",
}

# ===========================================================================
# Validation Constraints
# ===========================================================================

MIN_DELEGATION_CHAIN_LENGTH: int = 2
"""
Minimum entries in delegation_chain (human + agent).

§164.312(d) requires that access to ePHI be traced to an authenticated
entity. For AI agents, this means the chain must include at least one
human authorizer and the agent itself.
"""

REQUIRED_ACTION_FIELDS: list[str] = [
    "action_id",
    "timestamp",
    "agent_id",
    "session_id",
    "workflow_id",
    "human_authorizer_id",
    "human_authorizer_role",
    "operation",
]
"""
Fields that must be present and non-empty for every audit record.
Missing any of these constitutes V-018 (Missing Required Fields).
"""
