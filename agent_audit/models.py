#!/usr/bin/env python3
"""
Data models for the AI Agent Audit Trail Generator.

Grounded in:
- HIPAA Security Rule §164.312 (Technical Safeguards)
- HIPAA Privacy Rule §164.502(b) (Minimum Necessary)
- NIST AI RMF 1.0 (Govern, Map, Measure, Manage)
- NIST SP 800-66r2 (HIPAA Security Rule Implementation Guide)
- ONC HTI-1 Final Rule (AI Transparency — FAVES principles)
- 2025 HIPAA Security Rule Amendments (encryption now mandatory)
- FDA AI/ML Guidance 2025 (ALCOA+, GMLP, PCCPs)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session


# ---------------------------------------------------------------------------
# SQLAlchemy base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


# ---------------------------------------------------------------------------
# Dataclass: AgentIdentity
# §164.312(a)(2)(i) — Unique User Identification
# §164.312(d)       — Person or Entity Authentication
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    """
    Represents a registered AI agent operating within the healthcare network.

    Implements §164.312(a)(2)(i): every AI agent must have a unique identifier,
    enabling complete identity tracking across all ePHI operations.
    Implements §164.312(d): agents must authenticate before any PHI access, with
    credentials managed to the same standard as human workforce credentials.

    Per 2025 HIPAA Security Rule amendments, credential rotation schedules and
    FIPS-validated authentication are now codified requirements.
    """

    # Identity
    agent_id: str                       # UUID — globally unique agent identifier
    agent_name: str                     # Human-readable name ("Clinical Doc Assistant v2.1")
    agent_type: str                     # One of AGENT_TYPES
    vendor: str                         # "Epic", "Nuance/DAX", "Abridge", "Custom", etc.
    model_type: str                     # "llm", "ml_classifier", "rule_engine", "hybrid"
    model_version: str                  # "gpt-4o", "claude-3.5-sonnet", "custom-bert-v2"
    deployment_env: str                 # "production", "staging", "development", "test"

    # Ownership — ties agent to accountable human (§164.308(a)(3) Workforce Security)
    owner_id: str                       # Employee ID of responsible human owner
    owner_role: str                     # "IT Director", "CMIO", "Data Scientist"
    department: str                     # "Radiology", "Emergency", "Primary Care"

    # Lifecycle
    registered_at: str                  # ISO 8601 registration timestamp
    last_authenticated: str             # ISO 8601 last successful auth
    status: str                         # "active", "suspended", "decommissioned", "under_review"

    # Risk classification (drives audit intensity)
    risk_tier: str                      # "critical", "high", "medium", "low"
    phi_scope: str                      # "individual_encounter", "patient_record", "department_wide", "organization_wide"

    # Authorization
    permissions: list[str] = field(default_factory=list)
    # e.g., ["read_patient_summary", "read_lab_results", "write_clinical_note"]

    # Business Associate Agreement — §164.308(b) Business Associate Contracts
    baa_reference: str = ""             # BAA document identifier for third-party agents

    # Authentication — §164.312(d) + 2025 amendments (MFA codified)
    authentication_method: str = "oauth2_client_credentials"
    # "oauth2_client_credentials", "mtls", "api_key", "saml", "mfa_token"
    credential_rotation_days: int = 90  # Days between mandatory credential rotation
    last_credential_rotation: str = ""  # ISO 8601

    # ONC HTI-1 transparency metadata
    tags: dict = field(default_factory=dict)
    # Flexible metadata: intended_use, training_data_cutoff, faves_assessment_url, etc.

    def to_dict(self) -> dict:
        """Serialize to dict for storage and hashing."""
        return asdict(self)

    @property
    def credential_age_days(self) -> int:
        """Days since last credential rotation. Used for V-007 stale credential detection."""
        if not self.last_credential_rotation:
            return 9999
        try:
            last = datetime.fromisoformat(self.last_credential_rotation)
            now = datetime.now(timezone.utc)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            return (now - last).days
        except ValueError:
            return 9999

    @property
    def is_third_party(self) -> bool:
        """True if agent is from an external vendor (requires BAA per §164.308(b))."""
        return self.vendor.lower() not in {"custom", "internal", "in-house"}


# Controlled vocabulary for agent_type
AGENT_TYPES = {
    "clinical_documentation",
    "prior_auth",
    "triage",
    "scheduling",
    "coding",
    "research",
    "chatbot",
    "decision_support",
    "diagnostic_imaging",
    "medication_management",
    "billing",
    "population_health",
}


# ---------------------------------------------------------------------------
# Dataclass: AgentAction
# §164.312(b) — Audit Controls (the core audit record)
# ---------------------------------------------------------------------------

@dataclass
class AgentAction:
    """
    Represents a single atomic action performed by an AI agent on ePHI.

    This is the fundamental unit of the audit trail. Every field maps to a specific
    HIPAA technical safeguard requirement or NIST control.

    §164.312(b): Implement hardware, software, and/or procedural mechanisms that
    record and examine activity in information systems containing ePHI.

    Per NIST SP 800-66r2 guidance for AI systems, audit records must capture:
    agent identity, human authorizer, specific operation, PHI scope, policy context,
    tamper-evident timestamps, and data classification.

    Tamper evidence is implemented via a SHA-256 hash chain (blockchain-style):
    each record's previous_hash links to the prior record's record_hash,
    making undetected modification or deletion impossible.
    """

    # -------------------------------------------------------------------------
    # Core identifiers
    # -------------------------------------------------------------------------
    action_id: str                      # UUID — unique audit record identifier
    timestamp: str                      # ISO 8601 with timezone (e.g., 2026-04-07T12:00:00Z)
    agent_id: str                       # Links to AgentIdentity.agent_id
    session_id: str                     # Groups related operations in a workflow
    workflow_id: str                    # Clinical workflow (e.g., "discharge_summary_gen_12345")

    # -------------------------------------------------------------------------
    # WHO — §164.312(d) Person or Entity Authentication
    # Every agent action must be traceable to an authorizing human.
    # -------------------------------------------------------------------------
    human_authorizer_id: str            # Employee ID of the human who initiated the workflow
    human_authorizer_role: str          # "Attending Physician", "RN", "Medical Coder"
    delegation_chain: list[str] = field(default_factory=list)
    # Full delegation chain, e.g.:
    # ["Dr. Jane Smith (NPI: 1234567890)", "Clinical Workflow Engine v3.2", "DAX Copilot Agent"]
    # Minimum length: 2 (human + agent). Required per §164.312(d).

    # -------------------------------------------------------------------------
    # WHAT — §164.312(b) Audit Controls
    # -------------------------------------------------------------------------
    operation: str = "read"
    # "read", "write", "query", "upload", "download", "delete",
    # "transmit", "transform", "summarize", "classify", "authenticate"
    operation_detail: str = ""          # Free-text description of specific operation
    resource_type: str = ""
    # "patient_record", "lab_result", "radiology_report", "medication_list",
    # "clinical_note", "insurance_claim", "vital_signs", "imaging_study"
    resource_id: str = ""               # Specific record identifier (pseudonymized in reports)

    # -------------------------------------------------------------------------
    # PHI Classification — drives minimum necessary analysis (§164.502(b))
    # -------------------------------------------------------------------------
    phi_categories: list[str] = field(default_factory=list)
    # Standard PHI taxonomy (18 HIPAA identifiers + clinical categories):
    # "demographics", "diagnosis", "medications", "lab_values", "vitals",
    # "procedures", "insurance", "ssn", "mrn", "dob", "address", "phone",
    # "email", "account_number", "imaging", "genomics", "mental_health", "substance_use"
    phi_volume: int = 0                 # Number of distinct patient records accessed
    data_classification: str = "phi"
    # "pii", "phi", "limited_dataset", "de_identified", "non_phi"

    # -------------------------------------------------------------------------
    # WHERE — systems involved
    # -------------------------------------------------------------------------
    source_system: str = ""             # "Epic EHR", "Cerner", "PACS", "Lab Information System"
    target_system: str = ""             # "Clinical Documentation Module", "Patient Portal"
    network_zone: str = "internal_clinical"
    # "internal_clinical", "dmz", "external", "cloud_hipaa", "cloud_non_hipaa"

    # -------------------------------------------------------------------------
    # CONTEXT — §164.502(b) Minimum Necessary
    # "A covered entity must make reasonable efforts to limit PHI to the minimum
    # necessary to accomplish the intended purpose."
    # -------------------------------------------------------------------------
    access_justification: str = ""     # "Generating discharge summary for encounter #12345"
    minimum_necessary_scope: str = "encounter_specific"
    # "encounter_specific", "patient_specific", "department_wide", "unrestricted"
    policy_applied: str = ""           # Which access policy governed this action

    # -------------------------------------------------------------------------
    # SECURITY — §164.312(e) Transmission Security
    # §164.312(a)(2)(iv) Encryption and Decryption
    # 2025 Amendment: encryption is now MANDATORY (no longer merely addressable)
    # -------------------------------------------------------------------------
    encryption_in_transit: bool = True
    encryption_at_rest: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    # "AES-256-GCM", "AES-256-CBC", "TLS-1.3", "TLS-1.2", "none"
    fips_validated: bool = False        # FIPS 140-3 validated cryptographic module

    # -------------------------------------------------------------------------
    # INTEGRITY — §164.312(c) Integrity Controls
    # FDA ALCOA+: Attributable, Legible, Contemporaneous, Original, Accurate
    # -------------------------------------------------------------------------
    input_hash: str = ""               # SHA-256 of data provided to the agent
    output_hash: str = ""              # SHA-256 of data produced by the agent
    data_modified: bool = False        # Did the agent alter any ePHI?
    modification_type: str = "none"
    # "none", "summarization", "classification", "creation", "correction", "deletion"

    # -------------------------------------------------------------------------
    # OUTCOME
    # -------------------------------------------------------------------------
    status: str = "completed"
    # "completed", "failed", "denied", "timeout", "partial"
    error_message: str = ""
    duration_ms: int = 0               # Processing time in milliseconds

    # -------------------------------------------------------------------------
    # TAMPER EVIDENCE — append-only hash chain (§164.312(b))
    # Implements blockchain-style integrity: each record links to the previous.
    # Deletion or modification of any record breaks the chain, which is detected
    # by AuditStore.verify_chain_integrity().
    # -------------------------------------------------------------------------
    previous_hash: str = ""            # SHA-256 of the immediately preceding action record
    record_hash: str = ""              # SHA-256 of this complete record (set after all fields populated)
    chain_sequence: int = 0            # Monotonically increasing sequence number

    def to_dict(self) -> dict:
        """Serialize to dict for storage and hashing."""
        return asdict(self)

    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of this record (excluding record_hash itself).

        Used for tamper-evident chain integrity per §164.312(b) and
        NIST SP 800-92 (Guide to Computer Security Log Management).
        """
        d = asdict(self)
        d.pop("record_hash", None)      # Exclude field being computed
        canonical = json.dumps(d, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def involves_phi(self) -> bool:
        """True if this action involves PHI (used for encryption requirement checks)."""
        return self.data_classification in {"pii", "phi", "limited_dataset"}

    @property
    def is_external_transmission(self) -> bool:
        """True if data was transmitted outside the clinical network."""
        return self.network_zone in {"external", "cloud_non_hipaa", "dmz"}


# ---------------------------------------------------------------------------
# Dataclass: ComplianceControl
# Maps audit findings to specific HIPAA, NIST CSF, and NIST 800-53 controls
# ---------------------------------------------------------------------------

@dataclass
class ComplianceControl:
    """
    Represents a single compliance control requirement with assessment results.

    Maps to the full HIPAA Technical Safeguards (§164.312), NIST CSF categories,
    NIST SP 800-53 controls, and NIST AI RMF functions for comprehensive
    compliance posture reporting.

    Per NIST SP 800-66r2 §4.1, each addressable implementation specification
    requires the covered entity to assess whether it is reasonable and appropriate.
    Required specifications have no such flexibility — they must be implemented.
    """

    # Control identification
    control_id: str                     # "AC-001", "AU-001", "RM-001", etc.
    hipaa_section: str                  # "§164.312(a)(2)(i)"
    hipaa_standard: str                 # "Access Control — Unique User Identification"
    requirement_type: str               # "required" or "addressable"
    description: str                    # What the control requires

    # Framework cross-references (for multi-framework compliance reporting)
    nist_csf_mapping: str = ""          # "PR.AC-1", "DE.CM-3", etc.
    nist_800_53_mapping: str = ""       # "IA-2", "AU-2", "SC-28", etc.
    nist_ai_rmf_function: str = ""      # "Govern", "Map", "Measure", "Manage"

    # Audit methodology
    test_procedure: str = ""            # How auditors verify this control
    evidence_required: list[str] = field(default_factory=list)
    # What documentation/artifacts must be produced

    # Assessment results (populated by ComplianceEngine.assess_control())
    status: str = "not_assessed"
    # "compliant", "non_compliant", "partially_compliant", "not_assessed"
    finding: str = ""                   # Specific finding text (populated during assessment)
    severity: str = "informational"
    # "critical", "high", "medium", "low", "informational"
    risk_score: float = 0.0             # 0.0–10.0 CVSS-inspired risk score
    remediation: str = ""               # Recommended corrective action
    remediation_deadline: str = ""      # ISO 8601 target date
    evidence_collected: list[str] = field(default_factory=list)
    # Actual evidence gathered during assessment

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_critical_finding(self) -> bool:
        return self.status == "non_compliant" and self.severity in {"critical", "high"}

    @property
    def weight(self) -> float:
        """Scoring weight — required controls count 2x per §164.306(b)(2)."""
        return 2.0 if self.requirement_type == "required" else 1.0


# ---------------------------------------------------------------------------
# Dataclass: ViolationRecord
# Detected compliance issues with full evidentiary record
# ---------------------------------------------------------------------------

@dataclass
class ViolationRecord:
    """
    A specific, detected compliance violation tied to an agent action.

    Violations are detected by ViolationDetector and stored with full
    evidentiary records to support breach investigation, OCR reporting,
    and corrective action planning.

    Per 45 CFR §164.404, a HIPAA breach determination requires assessment of
    PHI impact, patient count, and whether there is "low probability of compromise."
    These fields directly support that four-factor analysis.
    """

    violation_id: str                   # UUID
    timestamp: str                      # ISO 8601 detection timestamp
    agent_id: str                       # Agent that committed the violation
    action_id: str                      # The specific action that triggered detection

    # Classification
    violation_type: str                 # See VIOLATION_TYPES below
    hipaa_section: str                  # Which HIPAA section was violated
    severity: str                       # "critical", "high", "medium", "low"
    severity_score: float               # 0.0–10.0

    # Description and evidence
    description: str = ""              # Human-readable plain-English description
    evidence: dict = field(default_factory=dict)
    # Structured evidence: {"field": "encryption_in_transit", "value": False, ...}

    # PHI impact assessment — supports 45 CFR §164.402 breach probability analysis
    phi_impact: str = "potential_phi_exposure"
    # "confirmed_phi_exposure", "potential_phi_exposure", "no_phi_impact"
    patient_count: int = 0             # Patients potentially affected

    # Remediation tracking
    status: str = "open"
    # "open", "acknowledged", "remediated", "accepted_risk", "false_positive"
    remediation_action: str = ""
    remediation_owner: str = ""        # Who is responsible for fixing this
    remediation_deadline: str = ""     # ISO 8601
    resolved_at: str = ""              # ISO 8601 actual resolution timestamp

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_reportable_breach(self) -> bool:
        """
        Heuristic for whether this violation may constitute a reportable breach
        under §164.402. Covered entities must notify HHS/patients within 60 days.
        """
        return (
            self.phi_impact == "confirmed_phi_exposure"
            and self.severity in {"critical", "high"}
            and self.patient_count > 0
        )


# Controlled vocabulary for violation_type
VIOLATION_TYPES = {
    "unauthorized_access",
    "missing_authentication",
    "unencrypted_phi",
    "excessive_scope",
    "missing_audit_log",
    "unlinked_human_authorizer",
    "stale_credentials",
    "phi_leak_to_external",
    "missing_baa",
    "minimum_necessary_violation",
    "bulk_phi_exfiltration",
    "scope_drift",
    "shadow_agent",
    "audit_chain_gap",
    "non_fips_encryption",
    "excessive_session_duration",
    "incomplete_delegation_chain",
    "deprecated_agent_active",
    "missing_operation_detail",
    "redundant_phi_access",
}


# ---------------------------------------------------------------------------
# Dataclass: ComplianceReport
# Top-level report artifact produced for CISO/compliance officer review
# ---------------------------------------------------------------------------

@dataclass
class ComplianceReport:
    """
    Comprehensive compliance report covering an assessment period.

    Structured to support:
    - Internal CISO and compliance officer review
    - OCR audit response preparation
    - NIST AI RMF posture reporting
    - ONC HTI-1 transparency attestation
    - Board-level risk reporting

    Report structure follows ISACA AI Audit framework:
    1. Executive Summary → 2. Scope → 3. Methodology → 4. Findings → 5. Remediation
    """

    report_id: str
    generated_at: str                   # ISO 8601
    report_period_start: str            # ISO 8601
    report_period_end: str              # ISO 8601
    organization_name: str

    # -------------------------------------------------------------------------
    # Executive summary
    # -------------------------------------------------------------------------
    overall_score: float = 0.0          # 0–100 weighted compliance score
    overall_rating: str = "Not Assessed"
    # "Compliant (≥90)", "Substantially Compliant (75–89)",
    # "Partially Compliant (50–74)", "Non-Compliant (<50)", "Critical (<25)"

    # -------------------------------------------------------------------------
    # Agent inventory
    # -------------------------------------------------------------------------
    total_agents: int = 0
    agents_by_risk_tier: dict = field(default_factory=dict)
    # {"critical": 2, "high": 5, "medium": 12, "low": 8}
    agents_by_status: dict = field(default_factory=dict)
    # {"active": 24, "suspended": 2, "decommissioned": 1, "under_review": 0}

    # -------------------------------------------------------------------------
    # Action telemetry
    # -------------------------------------------------------------------------
    total_actions: int = 0
    actions_by_operation: dict = field(default_factory=dict)
    actions_by_phi_category: dict = field(default_factory=dict)
    phi_records_accessed: int = 0

    # -------------------------------------------------------------------------
    # Compliance posture
    # -------------------------------------------------------------------------
    controls_assessed: int = 0
    controls_compliant: int = 0
    controls_non_compliant: int = 0
    controls_partially_compliant: int = 0

    # -------------------------------------------------------------------------
    # Violations
    # -------------------------------------------------------------------------
    total_violations: int = 0
    violations_by_severity: dict = field(default_factory=dict)
    # {"critical": 3, "high": 8, "medium": 12, "low": 20}
    violations_by_type: dict = field(default_factory=dict)
    open_violations: int = 0
    remediated_violations: int = 0

    # -------------------------------------------------------------------------
    # Risk assessment
    # -------------------------------------------------------------------------
    top_risks: list[dict] = field(default_factory=list)
    # [{"rank": 1, "description": "...", "affected_agents": 3, "hipaa_section": "§164.312(e)"}]

    # -------------------------------------------------------------------------
    # NIST AI RMF alignment scores (0.0–1.0 per function)
    # -------------------------------------------------------------------------
    nist_ai_rmf_scores: dict = field(default_factory=dict)
    # {"govern": 0.7, "map": 0.8, "measure": 0.6, "manage": 0.5}

    # -------------------------------------------------------------------------
    # Recommendations (priority-ordered)
    # -------------------------------------------------------------------------
    recommendations: list[dict] = field(default_factory=list)
    # [{"priority": 1, "title": "...", "description": "...", "hipaa_ref": "...", "effort": "low"}]

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def compliance_rate(self) -> float:
        """Fraction of assessed controls that are fully compliant."""
        if self.controls_assessed == 0:
            return 0.0
        return self.controls_compliant / self.controls_assessed

    @property
    def critical_violation_count(self) -> int:
        return self.violations_by_severity.get("critical", 0)


# ===========================================================================
# SQLAlchemy ORM Table Definitions
# Mirrors the dataclasses above for persistent SQLite storage.
# ---------------------------------------------------------------------------
# Design principles:
#   - Action records are APPEND-ONLY (no UPDATE/DELETE)
#   - Hash chain column enables tamper-evidence verification
#   - JSON columns used for list/dict fields (SQLite-compatible)
# ===========================================================================

class AgentIdentityORM(Base):
    """
    ORM model for AgentIdentity.
    §164.312(a)(2)(i) — Unique User Identification registry.
    """
    __tablename__ = "agent_identities"

    agent_id = Column(String, primary_key=True, index=True)
    agent_name = Column(String, nullable=False)
    agent_type = Column(String, nullable=False)
    vendor = Column(String, nullable=False)
    model_type = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    deployment_env = Column(String, nullable=False)
    owner_id = Column(String, nullable=False)
    owner_role = Column(String, nullable=False)
    department = Column(String, nullable=False)
    registered_at = Column(String, nullable=False)
    last_authenticated = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    risk_tier = Column(String, nullable=False, default="medium")
    phi_scope = Column(String, nullable=False, default="patient_record")
    permissions = Column(JSON, nullable=False, default=list)
    baa_reference = Column(String, default="")
    authentication_method = Column(String, default="oauth2_client_credentials")
    credential_rotation_days = Column(Integer, default=90)
    last_credential_rotation = Column(String, default="")
    tags = Column(JSON, default=dict)

    def to_dataclass(self) -> AgentIdentity:
        return AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            agent_type=self.agent_type,
            vendor=self.vendor,
            model_type=self.model_type,
            model_version=self.model_version,
            deployment_env=self.deployment_env,
            owner_id=self.owner_id,
            owner_role=self.owner_role,
            department=self.department,
            registered_at=self.registered_at,
            last_authenticated=self.last_authenticated,
            status=self.status,
            risk_tier=self.risk_tier,
            phi_scope=self.phi_scope,
            permissions=self.permissions or [],
            baa_reference=self.baa_reference or "",
            authentication_method=self.authentication_method or "oauth2_client_credentials",
            credential_rotation_days=self.credential_rotation_days or 90,
            last_credential_rotation=self.last_credential_rotation or "",
            tags=self.tags or {},
        )


class AgentActionORM(Base):
    """
    ORM model for AgentAction.
    §164.312(b) — Audit Controls. APPEND-ONLY table.

    The hash chain (previous_hash / record_hash / chain_sequence) implements
    tamper-evident logging. Any modification, insertion, or deletion breaks
    the chain, detectable by AuditStore.verify_chain_integrity().
    """
    __tablename__ = "agent_actions"

    action_id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    session_id = Column(String, nullable=False, index=True)
    workflow_id = Column(String, nullable=False, index=True)

    human_authorizer_id = Column(String, nullable=False, index=True)
    human_authorizer_role = Column(String, nullable=False)
    delegation_chain = Column(JSON, default=list)

    operation = Column(String, nullable=False, index=True)
    operation_detail = Column(Text, default="")
    resource_type = Column(String, default="")
    resource_id = Column(String, default="", index=True)

    phi_categories = Column(JSON, default=list)
    phi_volume = Column(Integer, default=0)
    data_classification = Column(String, default="phi", index=True)

    source_system = Column(String, default="")
    target_system = Column(String, default="")
    network_zone = Column(String, default="internal_clinical")

    access_justification = Column(Text, default="")
    minimum_necessary_scope = Column(String, default="encounter_specific")
    policy_applied = Column(String, default="")

    encryption_in_transit = Column(Boolean, default=True)
    encryption_at_rest = Column(Boolean, default=True)
    encryption_algorithm = Column(String, default="AES-256-GCM")
    fips_validated = Column(Boolean, default=False)

    input_hash = Column(String, default="")
    output_hash = Column(String, default="")
    data_modified = Column(Boolean, default=False)
    modification_type = Column(String, default="none")

    status = Column(String, default="completed", index=True)
    error_message = Column(Text, default="")
    duration_ms = Column(Integer, default=0)

    # Tamper-evidence chain fields
    previous_hash = Column(String, nullable=False, default="0" * 64)
    record_hash = Column(String, nullable=False, default="")
    chain_sequence = Column(Integer, nullable=False, default=0, index=True)

    def to_dataclass(self) -> AgentAction:
        return AgentAction(
            action_id=self.action_id,
            timestamp=self.timestamp,
            agent_id=self.agent_id,
            session_id=self.session_id,
            workflow_id=self.workflow_id,
            human_authorizer_id=self.human_authorizer_id,
            human_authorizer_role=self.human_authorizer_role,
            delegation_chain=self.delegation_chain or [],
            operation=self.operation,
            operation_detail=self.operation_detail or "",
            resource_type=self.resource_type or "",
            resource_id=self.resource_id or "",
            phi_categories=self.phi_categories or [],
            phi_volume=self.phi_volume or 0,
            data_classification=self.data_classification or "phi",
            source_system=self.source_system or "",
            target_system=self.target_system or "",
            network_zone=self.network_zone or "internal_clinical",
            access_justification=self.access_justification or "",
            minimum_necessary_scope=self.minimum_necessary_scope or "encounter_specific",
            policy_applied=self.policy_applied or "",
            encryption_in_transit=self.encryption_in_transit if self.encryption_in_transit is not None else True,
            encryption_at_rest=self.encryption_at_rest if self.encryption_at_rest is not None else True,
            encryption_algorithm=self.encryption_algorithm or "AES-256-GCM",
            fips_validated=self.fips_validated if self.fips_validated is not None else False,
            input_hash=self.input_hash or "",
            output_hash=self.output_hash or "",
            data_modified=self.data_modified if self.data_modified is not None else False,
            modification_type=self.modification_type or "none",
            status=self.status or "completed",
            error_message=self.error_message or "",
            duration_ms=self.duration_ms or 0,
            previous_hash=self.previous_hash or "0" * 64,
            record_hash=self.record_hash or "",
            chain_sequence=self.chain_sequence or 0,
        )


class ViolationRecordORM(Base):
    """
    ORM model for ViolationRecord.
    Stores detected compliance violations with full evidence records.
    """
    __tablename__ = "violation_records"

    violation_id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    action_id = Column(String, nullable=False, index=True)

    violation_type = Column(String, nullable=False, index=True)
    hipaa_section = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    severity_score = Column(Float, nullable=False)

    description = Column(Text, default="")
    evidence = Column(JSON, default=dict)
    phi_impact = Column(String, default="potential_phi_exposure")
    patient_count = Column(Integer, default=0)

    status = Column(String, default="open", index=True)
    remediation_action = Column(Text, default="")
    remediation_owner = Column(String, default="")
    remediation_deadline = Column(String, default="")
    resolved_at = Column(String, default="")

    def to_dataclass(self) -> ViolationRecord:
        return ViolationRecord(
            violation_id=self.violation_id,
            timestamp=self.timestamp,
            agent_id=self.agent_id,
            action_id=self.action_id,
            violation_type=self.violation_type,
            hipaa_section=self.hipaa_section,
            severity=self.severity,
            severity_score=self.severity_score,
            description=self.description or "",
            evidence=self.evidence or {},
            phi_impact=self.phi_impact or "potential_phi_exposure",
            patient_count=self.patient_count or 0,
            status=self.status or "open",
            remediation_action=self.remediation_action or "",
            remediation_owner=self.remediation_owner or "",
            remediation_deadline=self.remediation_deadline or "",
            resolved_at=self.resolved_at or "",
        )


class ComplianceReportORM(Base):
    """
    ORM model for persisted ComplianceReport metadata.
    Full report content is stored as JSON in report_json.
    """
    __tablename__ = "compliance_reports"

    report_id = Column(String, primary_key=True, index=True)
    generated_at = Column(String, nullable=False)
    report_period_start = Column(String, nullable=False)
    report_period_end = Column(String, nullable=False)
    organization_name = Column(String, nullable=False)
    overall_score = Column(Float, default=0.0)
    overall_rating = Column(String, default="Not Assessed")
    report_json = Column(JSON, default=dict)  # Full serialized ComplianceReport


class AuditChainMetaORM(Base):
    """
    Stores audit chain metadata for integrity verification.
    Tracks the genesis hash and current chain head.
    """
    __tablename__ = "audit_chain_meta"

    key = Column(String, primary_key=True)   # "genesis_hash", "last_hash", "total_records"
    value = Column(Text, nullable=False)


def get_engine(db_path: str):
    """Create SQLAlchemy engine with WAL mode for concurrent access safety."""
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    # Enable WAL mode for better concurrent read performance
    with engine.connect() as conn:
        conn.execute(__import__("sqlalchemy").text("PRAGMA journal_mode=WAL"))
        conn.execute(__import__("sqlalchemy").text("PRAGMA synchronous=FULL"))
        conn.execute(__import__("sqlalchemy").text("PRAGMA foreign_keys=ON"))
    return engine


def init_db(engine) -> None:
    """Create all tables if they don't exist."""
    Base.metadata.create_all(engine)
