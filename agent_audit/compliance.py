#!/usr/bin/env python3
"""
HIPAA compliance mapping engine.

Implements a full control library covering all §164.312 Technical Safeguards,
§164.502(b) Minimum Necessary, NIST AI RMF functions, and 2025 HIPAA Security
Rule amendments.

Each control assessment queries real data from the AuditStore — findings are
grounded in evidence, not assumptions.

HIPAA grounding:
  §164.312(a)  — Access Control
  §164.312(b)  — Audit Controls
  §164.312(c)  — Integrity
  §164.312(d)  — Person or Entity Authentication
  §164.312(e)  — Transmission Security
  §164.502(b)  — Minimum Necessary
  §164.308(b)  — Business Associate Contracts (BAA requirement)
  NIST AI RMF  — Govern, Map, Measure, Manage
  ONC HTI-1    — AI Transparency (FAVES)
"""

from __future__ import annotations

import copy
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .config import (
    ADDRESSABLE_CONTROL_WEIGHT,
    BULK_ACCESS_THRESHOLD,
    CREDENTIAL_ROTATION_MAX_DAYS,
    MAX_SESSION_HOURS,
    RATING_COMPLIANT_THRESHOLD,
    RATING_CRITICAL_THRESHOLD,
    RATING_PARTIAL_THRESHOLD,
    RATING_SUBSTANTIAL_THRESHOLD,
    REQUIRED_CONTROL_WEIGHT,
)
from .models import (
    AgentAction,
    AgentIdentity,
    ComplianceControl,
    ComplianceReport,
)

if TYPE_CHECKING:
    from .storage import AuditStore

logger = logging.getLogger(__name__)


# ===========================================================================
# HIPAA Control Library
# ~30 controls covering all §164.312 sections + NIST AI RMF
# ===========================================================================

HIPAA_CONTROLS: list[ComplianceControl] = [

    # -----------------------------------------------------------------------
    # AC — Access Control (§164.312(a))
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="AC-001",
        hipaa_section="§164.312(a)(2)(i)",
        hipaa_standard="Unique User Identification",
        requirement_type="required",
        description=(
            "Every AI agent must have a unique identifier assigned before it may access ePHI. "
            "Shared service accounts are prohibited. Unique IDs enable complete identity tracking "
            "and accountability across all ePHI operations."
        ),
        nist_csf_mapping="PR.AC-1",
        nist_800_53_mapping="IA-2",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Query agent registry and verify (a) no duplicate agent_ids exist, "
            "(b) all agents have non-empty agent_id values, "
            "(c) all action records reference a registered agent_id."
        ),
        evidence_required=[
            "Agent registry export showing unique IDs for all agents",
            "No shared credentials between agents",
            "Confirmation that all action records link to registered agent IDs",
        ],
    ),

    ComplianceControl(
        control_id="AC-002",
        hipaa_section="§164.312(a)(2)(i)",
        hipaa_standard="Unique User Identification — Human Delegation Traceability",
        requirement_type="required",
        description=(
            "Every AI agent action must be traceable to a human authorizer via a complete "
            "delegation chain. AI agents are SOFTWARE acting on behalf of human principals — "
            "§164.312(a)(1) explicitly includes software programs in access control scope. "
            "Unlinked agent actions constitute an §164.312(d) authentication failure."
        ),
        nist_csf_mapping="PR.AC-4",
        nist_800_53_mapping="AC-2",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify all action records have non-empty human_authorizer_id and "
            "delegation_chain with ≥2 entries. Calculate percentage of compliant records."
        ),
        evidence_required=[
            "Sample of action records with complete delegation chains",
            "Human authorizer validation records",
            "Zero tolerance for actions with empty human_authorizer_id",
        ],
    ),

    ComplianceControl(
        control_id="AC-003",
        hipaa_section="§164.312(a)(2)(ii)",
        hipaa_standard="Emergency Access Procedure",
        requirement_type="required",
        description=(
            "Procedures must exist for obtaining necessary ePHI during emergencies. "
            "AI agents with emergency access mode must be identifiable and their emergency "
            "activations separately logged and reviewed."
        ),
        nist_csf_mapping="PR.AC-4",
        nist_800_53_mapping="AC-14",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify agents have documented emergency access procedures. "
            "Check that emergency access activations in the audit log are followed by "
            "post-event review records."
        ),
        evidence_required=[
            "Emergency access procedure documentation",
            "List of agents with emergency access capability",
            "Review records for any emergency accesses in the period",
        ],
    ),

    ComplianceControl(
        control_id="AC-004",
        hipaa_section="§164.312(a)(2)(iii)",
        hipaa_standard="Automatic Logoff",
        requirement_type="addressable",
        description=(
            "AI agent sessions must be automatically terminated after a defined maximum duration "
            "or period of inactivity. §164.312(a)(2)(iii) requires mechanisms to terminate "
            "electronic sessions. For agents, this means session tokens/credentials must expire "
            "and agents must re-authenticate."
        ),
        nist_csf_mapping="PR.AC-7",
        nist_800_53_mapping="AC-12",
        nist_ai_rmf_function="Manage",
        test_procedure=(
            f"Identify sessions exceeding {MAX_SESSION_HOURS} hours duration. "
            "Verify session_ids are not reused across more than one operational day."
        ),
        evidence_required=[
            f"Session duration policy documenting {MAX_SESSION_HOURS}-hour maximum",
            "Session termination configuration for each agent type",
            "No sessions exceeding maximum duration in audit log",
        ],
    ),

    ComplianceControl(
        control_id="AC-005",
        hipaa_section="§164.312(a)(2)(iv)",
        hipaa_standard="Encryption and Decryption — At Rest",
        requirement_type="required",  # Was addressable; 2025 amendment made mandatory
        description=(
            "All ePHI stored by AI agents must be encrypted. "
            "Per the 2025 HIPAA Security Rule amendments, encryption at rest is now a "
            "REQUIRED safeguard (no longer merely addressable). AES-256-GCM with FIPS 140-3 "
            "validated modules is the recommended standard."
        ),
        nist_csf_mapping="PR.DS-1",
        nist_800_53_mapping="SC-28",
        nist_ai_rmf_function="Manage",
        test_procedure=(
            "Verify all action records accessing PHI have encryption_at_rest=True. "
            "Check encryption_algorithm is in the approved list."
        ),
        evidence_required=[
            "Encryption configuration for all agent data stores",
            "FIPS 140-3 certificate numbers for encryption modules",
            "100% of PHI actions show encryption_at_rest=True",
        ],
    ),

    ComplianceControl(
        control_id="AC-006",
        hipaa_section="§164.312(a)(1)",
        hipaa_standard="Access Control — Role-Based Enforcement",
        requirement_type="required",
        description=(
            "Access to ePHI must be based on assigned roles and minimum required permissions. "
            "AI agents must operate under the principle of least privilege — permissions must be "
            "scoped to the specific clinical workflow the agent supports, not broader."
        ),
        nist_csf_mapping="PR.AC-4",
        nist_800_53_mapping="AC-3",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify each agent's permissions list is non-empty and scoped. "
            "Check risk_tier matches permission scope. "
            "Flag agents with 'organization_wide' phi_scope and risk_tier below 'critical'."
        ),
        evidence_required=[
            "Permissions matrix for all agents",
            "Quarterly access review sign-off",
            "No agents with excessive permissions relative to their clinical function",
        ],
    ),

    ComplianceControl(
        control_id="AC-007",
        hipaa_section="§164.502(b)",
        hipaa_standard="Minimum Necessary — Operation-Level Enforcement",
        requirement_type="required",
        description=(
            "PHI access must be limited to the minimum necessary for each specific operation. "
            "§164.502(b) requires this enforcement at the operation level, not just the session "
            "level. System prompts alone do NOT constitute technical access controls."
        ),
        nist_csf_mapping="PR.DS-5",
        nist_800_53_mapping="AC-3",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify all action records have minimum_necessary_scope set. "
            "Flag any actions with minimum_necessary_scope='unrestricted' combined with "
            "non-critical workflows. Calculate rate of encounter_specific vs broader scope."
        ),
        evidence_required=[
            "Minimum necessary policy documentation",
            "Technical controls enforcing scope limits per operation type",
            "No unrestricted scope without documented clinical justification",
        ],
    ),

    ComplianceControl(
        control_id="AC-008",
        hipaa_section="§164.312(d)",
        hipaa_standard="Credential Rotation",
        requirement_type="required",
        description=(
            "AI agent credentials must be rotated on a defined schedule. "
            "Per 2025 HIPAA amendments, periodic re-authentication is now codified. "
            f"Maximum rotation interval: {CREDENTIAL_ROTATION_MAX_DAYS} days."
        ),
        nist_csf_mapping="PR.AC-1",
        nist_800_53_mapping="IA-5",
        nist_ai_rmf_function="Manage",
        test_procedure=(
            f"Check last_credential_rotation for all active agents. "
            f"Flag any agent where days since rotation > {CREDENTIAL_ROTATION_MAX_DAYS}."
        ),
        evidence_required=[
            "Credential rotation policy and schedule",
            "Rotation logs for all agents",
            f"All agents rotated within {CREDENTIAL_ROTATION_MAX_DAYS} days",
        ],
    ),

    # -----------------------------------------------------------------------
    # AU — Audit Controls (§164.312(b))
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="AU-001",
        hipaa_section="§164.312(b)",
        hipaa_standard="Audit Trail Completeness",
        requirement_type="required",
        description=(
            "Hardware, software, and/or procedural mechanisms must record and examine activity "
            "in systems containing ePHI. For AI agents, this requires capturing: agent identity, "
            "human authorizer, specific operation, PHI records accessed, policy context, "
            "tamper-evident timestamp, data classification, and source/target systems."
        ),
        nist_csf_mapping="DE.CM-3",
        nist_800_53_mapping="AU-2",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify all action records contain all required fields: "
            "action_id, timestamp, agent_id, human_authorizer_id, operation, "
            "resource_type, phi_categories, data_classification, source_system."
        ),
        evidence_required=[
            "Sample audit records demonstrating all required fields populated",
            "Field completeness rate ≥99% across all records",
            "Automated completeness checks in ingestion pipeline",
        ],
    ),

    ComplianceControl(
        control_id="AU-002",
        hipaa_section="§164.312(b)",
        hipaa_standard="Tamper-Evident Audit Log",
        requirement_type="required",
        description=(
            "Audit logs must be tamper-evident. This implementation uses a SHA-256 "
            "hash chain (blockchain-style) where each record cryptographically commits "
            "to all preceding records. Any modification, deletion, or insertion breaks "
            "the chain and is detected during integrity verification."
        ),
        nist_csf_mapping="PR.DS-6",
        nist_800_53_mapping="AU-9",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Run AuditStore.verify_chain_integrity() and confirm zero errors. "
            "Verify append-only database configuration (no UPDATE/DELETE on action table)."
        ),
        evidence_required=[
            "Hash chain integrity verification report (zero errors)",
            "Database configuration showing append-only access controls",
            "No direct database write access except through audit API",
        ],
    ),

    ComplianceControl(
        control_id="AU-003",
        hipaa_section="§164.312(b)",
        hipaa_standard="Operation-Level Audit Granularity",
        requirement_type="required",
        description=(
            "Audit records must capture individual operations, not just sessions or API calls. "
            "A single AI agent invocation may perform dozens of distinct PHI operations "
            "(read patient record, read labs, read medications, write summary) — each must "
            "be individually logged."
        ),
        nist_csf_mapping="DE.CM-3",
        nist_800_53_mapping="AU-3",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify operation_detail field is populated for PHI-access actions. "
            "Check that multi-step workflows generate multiple action records "
            "(one per distinct PHI operation)."
        ),
        evidence_required=[
            "Sample of multi-step workflow audit trails showing per-operation records",
            "operation_detail population rate",
        ],
    ),

    ComplianceControl(
        control_id="AU-004",
        hipaa_section="§164.312(b)",
        hipaa_standard="Real-Time Anomaly Detection Capability",
        requirement_type="addressable",
        description=(
            "Audit controls should include mechanisms to detect anomalies in real-time. "
            "NIST SP 800-66r2 recommends SIEM integration. The violation detector provides "
            "this capability — rules fire on each ingested action."
        ),
        nist_csf_mapping="DE.AE-2",
        nist_800_53_mapping="SI-4",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify ViolationDetector is configured and running. "
            "Confirm violations are detected on ingestion (not batched). "
            "Check that critical violations generate immediate alerts."
        ),
        evidence_required=[
            "ViolationDetector configuration",
            "Evidence of real-time violation firing on recent critical events",
        ],
    ),

    ComplianceControl(
        control_id="AU-005",
        hipaa_section="§164.316(b)(2)(i)",
        hipaa_standard="Audit Log Retention — 6 Years",
        requirement_type="required",
        description=(
            "HIPAA documentation and audit records must be retained for 6 years from "
            "the date of creation or the date last in effect, whichever is later. "
            "Audit logs are specifically called out in NIST SP 800-66r2 §4.6."
        ),
        nist_csf_mapping="PR.IP-4",
        nist_800_53_mapping="AU-11",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify database retention policy is set to ≥2190 days (6 years). "
            "Confirm no automated deletion or rotation of audit records before 6-year mark."
        ),
        evidence_required=[
            "Retention policy configuration (2190 days minimum)",
            "No records deleted before retention period",
            "Backup and disaster recovery plan covering audit database",
        ],
    ),

    ComplianceControl(
        control_id="AU-006",
        hipaa_section="§164.312(b)",
        hipaa_standard="Periodic Audit Log Review",
        requirement_type="addressable",
        description=(
            "Audit logs must be regularly reviewed. ISACA recommends 100% review completion "
            "on a quarterly basis. The compliance report generation capability supports this."
        ),
        nist_csf_mapping="DE.AE-3",
        nist_800_53_mapping="AU-6",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify compliance reports have been generated covering the assessment period. "
            "Confirm reports were reviewed and violations were acknowledged."
        ),
        evidence_required=[
            "Quarterly compliance reports signed by CISO or designee",
            "Evidence of violation review and remediation tracking",
        ],
    ),

    # -----------------------------------------------------------------------
    # IN — Integrity (§164.312(c))
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="IN-001",
        hipaa_section="§164.312(c)(1)",
        hipaa_standard="ePHI Integrity — Data Modification Tracking",
        requirement_type="required",
        description=(
            "ePHI must be protected from improper alteration or destruction. "
            "When AI agents modify ePHI (summarization, classification, correction), "
            "the modification must be logged with input_hash, output_hash, and modification_type."
        ),
        nist_csf_mapping="PR.DS-6",
        nist_800_53_mapping="SI-7",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "For all action records with data_modified=True, verify input_hash and "
            "output_hash are non-empty and distinct. Verify modification_type is set."
        ),
        evidence_required=[
            "Sample of modification records with populated hash fields",
            "100% of data_modified=True records have both hash fields",
        ],
    ),

    ComplianceControl(
        control_id="IN-002",
        hipaa_section="§164.312(c)(2)",
        hipaa_standard="Mechanism to Authenticate ePHI Integrity",
        requirement_type="addressable",
        description=(
            "A mechanism to corroborate that ePHI has not been altered or destroyed "
            "in an unauthorized manner. The SHA-256 input/output hash capture in every "
            "action record fulfills this requirement — downstream consumers can verify "
            "the agent received and produced the expected data."
        ),
        nist_csf_mapping="PR.DS-6",
        nist_800_53_mapping="SI-7",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify input_hash and output_hash fields are populated for PHI-read actions. "
            "Spot-check that hashes match expected SHA-256 of corresponding data."
        ),
        evidence_required=[
            "Sample verification of input/output hash accuracy",
            "Hash algorithm documentation (SHA-256, FIPS 180-4 compliant)",
        ],
    ),

    ComplianceControl(
        control_id="IN-003",
        hipaa_section="§164.312(b)",
        hipaa_standard="Audit Record Hash Chain Validation",
        requirement_type="required",
        description=(
            "The hash chain integrity of the audit record store must be periodically "
            "verified. Any break in the chain indicates tampering, which triggers "
            "an immediate incident response per §164.308(a)(6)."
        ),
        nist_csf_mapping="PR.DS-6",
        nist_800_53_mapping="AU-9",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Run AuditStore.verify_chain_integrity() and confirm (valid=True, errors=[]). "
            "Document last verification date and result."
        ),
        evidence_required=[
            "Chain integrity verification log showing True result",
            "Automated daily integrity check configured",
        ],
    ),

    # -----------------------------------------------------------------------
    # PA — Person/Entity Authentication (§164.312(d))
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="PA-001",
        hipaa_section="§164.312(d)",
        hipaa_standard="Entity Authentication — Agent Authentication Before PHI Access",
        requirement_type="required",
        description=(
            "AI agents must be authenticated before any access to ePHI. "
            "§164.312(d) requires verification that the entity is who it claims to be. "
            "For agents, this means a registered identity with verifiable credentials, "
            "not just an API key stored in plaintext."
        ),
        nist_csf_mapping="PR.AC-7",
        nist_800_53_mapping="IA-3",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify all agents have authentication_method set to an approved method. "
            "Confirm last_authenticated is populated and not stale. "
            "Zero tolerance for agents with authentication_method='none'."
        ),
        evidence_required=[
            "Authentication configuration for all agents",
            "No agents accessing PHI without documented authentication method",
        ],
    ),

    ComplianceControl(
        control_id="PA-002",
        hipaa_section="§164.312(d)",
        hipaa_standard="Delegation Chain Completeness",
        requirement_type="required",
        description=(
            "The full delegation chain from human authorizer through all intermediate "
            "systems to the AI agent must be captured in every action record. "
            "A delegation chain of length <2 (missing either the human or the agent) "
            "is a compliance failure."
        ),
        nist_csf_mapping="PR.AC-4",
        nist_800_53_mapping="AC-2",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify all action records have delegation_chain length ≥2. "
            "Check that the first entry in each chain identifies a human (not another system). "
            "Calculate rate of complete delegation chains."
        ),
        evidence_required=[
            "All action records have delegation chains ≥2 entries",
            "Sample chains showing human → system → agent structure",
        ],
    ),

    ComplianceControl(
        control_id="PA-003",
        hipaa_section="§164.312(d)",
        hipaa_standard="Authentication Method Strength",
        requirement_type="required",
        description=(
            "Per 2025 HIPAA amendments, multi-factor authentication (MFA) is now codified "
            "for workforce access to ePHI. AI agents accessing PHI must use strong "
            "authentication: OAuth 2.0 client credentials, mTLS, or SAML are acceptable. "
            "Plain API keys without additional factors are discouraged for high-risk agents."
        ),
        nist_csf_mapping="PR.AC-7",
        nist_800_53_mapping="IA-2(1)",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify critical and high risk_tier agents use strong auth methods "
            "(oauth2_client_credentials, mtls, or saml). "
            "Flag any critical-tier agent using 'api_key' without MFA."
        ),
        evidence_required=[
            "Authentication method inventory by risk tier",
            "No critical agents using weak authentication",
        ],
    ),

    ComplianceControl(
        control_id="PA-004",
        hipaa_section="§164.308(b)",
        hipaa_standard="Business Associate Agreement Coverage",
        requirement_type="required",
        description=(
            "Third-party AI agents (from external vendors) must operate under a valid "
            "Business Associate Agreement (BAA) per §164.308(b). The 2025 amendments "
            "extended direct Security Rule liability to business associates. "
            "An agent from Epic, Nuance, or any external vendor without a BAA reference "
            "is a critical compliance failure."
        ),
        nist_csf_mapping="GV.SC-4",
        nist_800_53_mapping="SA-9",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "For all third-party agents (vendor not in {'custom', 'internal'}), "
            "verify baa_reference is non-empty and references a valid BAA document. "
            "Calculate rate of third-party agents with BAA coverage."
        ),
        evidence_required=[
            "BAA documents for all third-party vendors",
            "100% of third-party agents have baa_reference populated",
        ],
    ),

    # -----------------------------------------------------------------------
    # TS — Transmission Security (§164.312(e))
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="TS-001",
        hipaa_section="§164.312(e)(2)(ii)",
        hipaa_standard="Encryption in Transit — Mandatory (2025 Amendment)",
        requirement_type="required",  # Was addressable; 2025 amendment made mandatory
        description=(
            "All ePHI transmitted by AI agents must be encrypted. "
            "Per the 2025 HIPAA Security Rule amendments, transmission encryption is now "
            "REQUIRED (previously addressable). TLS 1.3 minimum; TLS 1.2 allowed only "
            "with documented business justification."
        ),
        nist_csf_mapping="PR.DS-2",
        nist_800_53_mapping="SC-8",
        nist_ai_rmf_function="Manage",
        test_procedure=(
            "Verify all action records with data_classification in {phi, pii, limited_dataset} "
            "have encryption_in_transit=True. "
            "Flag any PHI actions with encryption_in_transit=False as CRITICAL violations."
        ),
        evidence_required=[
            "100% of PHI transmission actions show encryption_in_transit=True",
            "TLS configuration documentation for all agent communication paths",
        ],
    ),

    ComplianceControl(
        control_id="TS-002",
        hipaa_section="§164.312(e)(2)(ii)",
        hipaa_standard="FIPS 140-3 Validated Encryption",
        requirement_type="required",
        description=(
            "Per 2025 HIPAA amendments, FIPS 140-3 validated cryptographic modules are now "
            "required (not recommended). Using AES-256-GCM without a FIPS-validated module "
            "is insufficient. Healthcare organizations must source FIPS-validated TLS "
            "implementations for all agent communication paths."
        ),
        nist_csf_mapping="PR.DS-2",
        nist_800_53_mapping="SC-13",
        nist_ai_rmf_function="Manage",
        test_procedure=(
            "Verify fips_validated=True for all PHI action records. "
            "Obtain FIPS 140-3 certificate numbers for all encryption modules in use. "
            "Calculate FIPS compliance rate across PHI actions."
        ),
        evidence_required=[
            "FIPS 140-3 certificate numbers for all crypto modules",
            "FIPS compliance rate for PHI actions",
        ],
    ),

    ComplianceControl(
        control_id="TS-003",
        hipaa_section="§164.312(e)(2)(i)",
        hipaa_standard="Transmission Integrity Controls",
        requirement_type="addressable",
        description=(
            "Implement security measures to ensure ePHI is not improperly modified "
            "during transmission. The output_hash field captures the SHA-256 of agent "
            "output, enabling detection of in-transit modification."
        ),
        nist_csf_mapping="PR.DS-6",
        nist_800_53_mapping="SC-8(1)",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify output_hash is populated for all transmit operations. "
            "Confirm that message authentication (HMAC or AEAD mode like GCM) is used."
        ),
        evidence_required=[
            "output_hash population rate for transmit operations",
            "Documentation of AEAD (GCM) or HMAC usage for transmission integrity",
        ],
    ),

    ComplianceControl(
        control_id="TS-004",
        hipaa_section="§164.312(e)(1)",
        hipaa_standard="Network Segmentation and External PHI Transmission",
        requirement_type="required",
        description=(
            "PHI transmitted to external systems (network_zone='external' or 'cloud_non_hipaa') "
            "requires elevated scrutiny. Per 2025 amendments, network segmentation is now "
            "codified as a required safeguard. External PHI transmission without encryption "
            "and without a BAA constitutes a potential reportable breach."
        ),
        nist_csf_mapping="PR.AC-5",
        nist_800_53_mapping="SC-7",
        nist_ai_rmf_function="Manage",
        test_procedure=(
            "Identify all action records with network_zone in {external, cloud_non_hipaa}. "
            "Verify all external transmissions have encryption_in_transit=True. "
            "Cross-reference agent BAA coverage for external transmissions."
        ),
        evidence_required=[
            "Network segmentation diagram showing agent communication paths",
            "All external PHI transmissions encrypted",
            "BAA coverage confirmed for all external-zone agents",
        ],
    ),

    # -----------------------------------------------------------------------
    # MN — Minimum Necessary (§164.502(b))
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="MN-001",
        hipaa_section="§164.502(b)",
        hipaa_standard="Minimum Necessary — PHI Volume Monitoring",
        requirement_type="required",
        description=(
            "Covered entities must make reasonable efforts to limit PHI access to the "
            "minimum necessary. AI agents that access large volumes of patient records "
            f"(>{BULK_ACCESS_THRESHOLD} per session) must have documented justification "
            "or be flagged for review."
        ),
        nist_csf_mapping="PR.DS-5",
        nist_800_53_mapping="AC-3",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            f"Identify agent sessions where sum(phi_volume) > {BULK_ACCESS_THRESHOLD}. "
            "Verify access_justification is populated for these sessions. "
            "Flag any without justification as minimum necessary violations."
        ),
        evidence_required=[
            "Documentation of business justification for bulk-access agents",
            "No unexplained bulk PHI access patterns",
        ],
    ),

    ComplianceControl(
        control_id="MN-002",
        hipaa_section="§164.502(b)",
        hipaa_standard="Minimum Necessary — Access Justification Capture",
        requirement_type="required",
        description=(
            "Every agent action accessing PHI must include an access_justification "
            "field documenting why the specific PHI was needed for the task. "
            "System prompts do NOT constitute technical access controls — the justification "
            "must be captured at the operation level."
        ),
        nist_csf_mapping="PR.DS-5",
        nist_800_53_mapping="AC-3",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "For PHI-access actions, verify access_justification is non-empty. "
            "Calculate justification capture rate."
        ),
        evidence_required=[
            "≥95% of PHI actions have non-empty access_justification",
            "Sample of justifications showing operation-specific language",
        ],
    ),

    ComplianceControl(
        control_id="MN-003",
        hipaa_section="§164.502(b)",
        hipaa_standard="Scope Drift Detection",
        requirement_type="addressable",
        description=(
            "AI agents may gradually expand their PHI access scope over time through "
            "incremental workflow changes — a phenomenon called 'scope drift.' "
            "Regular comparison of current access patterns against baseline is required."
        ),
        nist_csf_mapping="DE.AE-3",
        nist_800_53_mapping="AC-2",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Run scope drift analysis over the past 30 days. "
            "Flag agents whose average phi_volume per action has increased >20% month-over-month."
        ),
        evidence_required=[
            "Scope drift analysis results",
            "Quarterly access pattern baseline snapshots",
        ],
    ),

    # -----------------------------------------------------------------------
    # RM — NIST AI RMF (Govern, Map, Measure, Manage)
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="RM-001",
        hipaa_section="§164.308(a)(1)",
        hipaa_standard="NIST AI RMF — Govern: AI Governance Framework",
        requirement_type="required",
        description=(
            "NIST AI RMF GOVERN function: Define policies, roles, and governance structures "
            "for healthcare AI. Per §164.308(a)(1), risk analysis must specifically inventory "
            "and assess AI systems accessing PHI. Every AI agent must have a documented owner, "
            "defined risk tier, and approved use case."
        ),
        nist_csf_mapping="GV.OC-1",
        nist_800_53_mapping="PL-2",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "Verify all registered agents have: owner_id, owner_role, department, risk_tier, "
            "and phi_scope populated. Calculate governance coverage rate."
        ),
        evidence_required=[
            "AI governance policy document",
            "Risk tier assignments for all agents with justification",
            "100% of agents have documented owner",
        ],
    ),

    ComplianceControl(
        control_id="RM-002",
        hipaa_section="§164.308(a)(1)",
        hipaa_standard="NIST AI RMF — Map: AI System Inventory and Risk Mapping",
        requirement_type="required",
        description=(
            "NIST AI RMF MAP function: Catalog all AI systems processing PHI or influencing "
            "care decisions. Identify potential harm scenarios. This agent registry IS the "
            "AI system inventory — it must be complete and current."
        ),
        nist_csf_mapping="ID.AM-2",
        nist_800_53_mapping="PM-5",
        nist_ai_rmf_function="Map",
        test_procedure=(
            "Verify shadow agent count = 0 (no unregistered agents in action logs). "
            "Confirm all active clinical AI systems appear in the registry. "
            "Check that decommissioned agents are marked appropriately, not deleted."
        ),
        evidence_required=[
            "Complete AI system inventory matching action log agent IDs",
            "Zero shadow agents detected",
            "Risk mapping document per NIST AI RMF MAP playbook",
        ],
    ),

    ComplianceControl(
        control_id="RM-003",
        hipaa_section="§164.308(a)(1)",
        hipaa_standard="NIST AI RMF — Measure/Manage: Continuous Monitoring",
        requirement_type="required",
        description=(
            "NIST AI RMF MEASURE and MANAGE functions: Define performance metrics and "
            "implement continuous monitoring for model drift, access anomalies, and "
            "adversarial attacks. This audit tool IS the continuous monitoring infrastructure."
        ),
        nist_csf_mapping="DE.CM-8",
        nist_800_53_mapping="CA-7",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify ViolationDetector is running and detecting anomalies. "
            "Confirm compliance reports are generated at least monthly. "
            "Check that critical violations are escalated within 24 hours."
        ),
        evidence_required=[
            "Monthly compliance report cadence",
            "Critical violation escalation SLA documentation",
            "Continuous monitoring configuration documentation",
        ],
    ),

    # -----------------------------------------------------------------------
    # OT — ONC HTI-1 / FDA Transparency
    # -----------------------------------------------------------------------

    ComplianceControl(
        control_id="OT-001",
        hipaa_section="ONC HTI-1",
        hipaa_standard="AI Transparency — FAVES Principles",
        requirement_type="addressable",
        description=(
            "ONC HTI-1 Rule requires predictive AI in certified health IT to meet FAVES: "
            "Fair, Appropriate, Valid, Effective, Safe. This requires documenting: "
            "intended use, cautioned uses, development details, demographic representativeness, "
            "real-world testing results. Captured in AgentIdentity.tags."
        ),
        nist_csf_mapping="GV.OC-5",
        nist_800_53_mapping="SA-4",
        nist_ai_rmf_function="Govern",
        test_procedure=(
            "For agents of type 'decision_support' or 'diagnostic_imaging', verify "
            "tags contain: intended_use, cautioned_uses, demographic_representativeness. "
            "Calculate ONC HTI-1 documentation coverage rate."
        ),
        evidence_required=[
            "ONC HTI-1 FAVES documentation for applicable agents",
            "Real-world testing results for decision support agents",
        ],
    ),

    ComplianceControl(
        control_id="OT-002",
        hipaa_section="FDA AI Guidance 2025",
        hipaa_standard="FDA ALCOA+ Compliance — Audit Record Quality",
        requirement_type="addressable",
        description=(
            "FDA ALCOA+ principles for AI/ML systems in healthcare: Attributable, Legible, "
            "Contemporaneous, Original, Accurate, Complete, Consistent, Enduring, Available. "
            "Every audit record must be attributable to an identified agent, contemporaneous "
            "(timestamped at time of action), and complete (all required fields populated)."
        ),
        nist_csf_mapping="PR.DS-6",
        nist_800_53_mapping="AU-3",
        nist_ai_rmf_function="Measure",
        test_procedure=(
            "Verify ALCOA+ compliance: "
            "(A) Attributable: agent_id and human_authorizer_id non-empty on all records. "
            "(C) Contemporaneous: timestamp within 5s of action. "
            "(C) Complete: all required fields populated. "
            "(E) Enduring: retention policy ≥6 years."
        ),
        evidence_required=[
            "ALCOA+ assessment report",
            "Field completeness rate by required field",
        ],
    ),
]


# ===========================================================================
# Compliance Engine
# ===========================================================================

class ComplianceEngine:
    """
    Assesses the organization's compliance posture against the full HIPAA control library.

    Each control is assessed by querying real data from the AuditStore — findings
    are evidence-based, not assumption-based.

    Usage::

        engine = ComplianceEngine(store=audit_store)
        results = engine.assess_all_controls("2026-01-01T00:00:00Z", "2026-04-07T23:59:59Z")
        score = engine.compute_compliance_score(results)
        report = engine.build_report(results, period_start, period_end, org_name)
    """

    def __init__(self, store: "AuditStore") -> None:
        """
        Initialize the compliance engine.

        Args:
            store: AuditStore instance for querying audit data.
        """
        self.store = store
        self.controls = HIPAA_CONTROLS

    # ------------------------------------------------------------------
    # Full assessment
    # ------------------------------------------------------------------

    def assess_all_controls(
        self,
        period_start: str,
        period_end: str,
    ) -> list[ComplianceControl]:
        """
        Run full compliance assessment against all controls for the given period.

        Each control's assess_* method queries the AuditStore and populates
        the status, finding, risk_score, and evidence_collected fields.

        Args:
            period_start: ISO 8601 start of assessment period
            period_end:   ISO 8601 end of assessment period

        Returns:
            List of ComplianceControl instances with assessment results populated.
        """
        actions = self.store.query_actions(start=period_start, end=period_end)
        agents = self.store.list_agents()

        results: list[ComplianceControl] = []
        for control in self.controls:
            assessed = self.assess_control(
                copy.deepcopy(control), actions, agents, period_start, period_end
            )
            results.append(assessed)
            logger.debug(
                "Control %s [%s]: %s (score=%.1f)",
                assessed.control_id, assessed.requirement_type,
                assessed.status, assessed.risk_score,
            )

        logger.info(
            "Assessed %d controls. Compliant: %d, Non-Compliant: %d, Partial: %d",
            len(results),
            sum(1 for r in results if r.status == "compliant"),
            sum(1 for r in results if r.status == "non_compliant"),
            sum(1 for r in results if r.status == "partially_compliant"),
        )
        return results

    def assess_control(
        self,
        control: ComplianceControl,
        actions: list[AgentAction],
        agents: list[AgentIdentity],
        period_start: str = "",
        period_end: str = "",
    ) -> ComplianceControl:
        """
        Assess a single control against the provided data.

        Dispatches to the appropriate control-specific assessment method.

        Args:
            control: The control to assess (deep-copied before modification).
            actions: Action records for the assessment period.
            agents:  All registered agents.
            period_start: Period start (for chain integrity check).
            period_end:   Period end.

        Returns:
            The control with status, finding, risk_score, evidence_collected populated.
        """
        method_name = f"_assess_{control.control_id.replace('-', '_').lower()}"
        method = getattr(self, method_name, self._assess_generic)
        return method(control, actions, agents)

    # ------------------------------------------------------------------
    # Individual control assessments
    # ------------------------------------------------------------------

    def _assess_ac_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-001: Unique agent identifiers — no duplicates, all non-empty."""
        agent_ids = [a.agent_id for a in agents]
        duplicates = len(agent_ids) - len(set(agent_ids))
        empty_ids = sum(1 for aid in agent_ids if not aid)
        action_agent_ids = {a.agent_id for a in actions}
        known_ids = set(agent_ids)
        unregistered = action_agent_ids - known_ids

        if duplicates > 0 or empty_ids > 0:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 9.5
            c.finding = (
                f"FAIL: {duplicates} duplicate agent_id(s), {empty_ids} empty agent_id(s). "
                f"Unique identification is a REQUIRED control — shared identities prevent "
                f"attribution of ePHI access."
            )
        elif unregistered:
            c.status = "partially_compliant"
            c.severity = "high"
            c.risk_score = 7.0
            c.finding = (
                f"PARTIAL: {len(unregistered)} unregistered agent(s) appearing in action logs: "
                f"{list(unregistered)[:5]}. These shadow agents are not in the identity registry."
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = (
                f"PASS: {len(agents)} agents registered, all with unique IDs. "
                f"All action records reference registered agents."
            )
        c.evidence_collected = [
            f"Total registered agents: {len(agents)}",
            f"Duplicate IDs: {duplicates}",
            f"Unregistered agents in action log: {len(unregistered)}",
        ]
        return c

    def _assess_ac_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-002: Human delegation traceability on all actions."""
        if not actions:
            c.status = "not_assessed"
            c.finding = "No actions in period."
            return c
        missing_auth = [a for a in actions if not a.human_authorizer_id or a.human_authorizer_id == "unknown_authorizer"]
        rate = 1.0 - len(missing_auth) / len(actions)
        if len(missing_auth) > 0:
            c.status = "non_compliant" if rate < 0.95 else "partially_compliant"
            c.severity = "critical" if rate < 0.95 else "high"
            c.risk_score = 9.5 if rate < 0.95 else 7.0
            c.finding = (
                f"{'FAIL' if rate < 0.95 else 'PARTIAL'}: "
                f"{len(missing_auth)}/{len(actions)} actions ({100*(1-rate):.1f}%) "
                f"lack a human authorizer ID. §164.312(d) requires every action to be "
                f"traceable to an authenticated human."
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(actions)} actions have human_authorizer_id populated."
        c.evidence_collected = [
            f"Actions with human_authorizer_id: {len(actions) - len(missing_auth)}/{len(actions)}",
            f"Delegation traceability rate: {rate:.1%}",
        ]
        return c

    def _assess_ac_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-003: Emergency access procedure — informational check."""
        # Check if any agents are tagged with emergency access capability
        emergency_agents = [a for a in agents if "emergency_access" in a.tags]
        c.status = "partially_compliant"
        c.severity = "medium"
        c.risk_score = 4.0
        c.finding = (
            f"{len(emergency_agents)} agent(s) tagged with emergency_access capability. "
            "Manual review required: verify emergency access procedure documentation exists "
            "and post-event reviews are conducted."
        )
        c.evidence_collected = [f"Agents with emergency access: {len(emergency_agents)}"]
        return c

    def _assess_ac_004(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-004: Automatic logoff — session duration check."""
        from collections import defaultdict
        session_durations: dict[str, list[str]] = defaultdict(list)
        for a in actions:
            session_durations[a.session_id].append(a.timestamp)
        long_sessions = []
        for sid, timestamps in session_durations.items():
            sorted_ts = sorted(timestamps)
            if len(sorted_ts) >= 2:
                try:
                    t_start = datetime.fromisoformat(sorted_ts[0])
                    t_end = datetime.fromisoformat(sorted_ts[-1])
                    if t_start.tzinfo is None:
                        t_start = t_start.replace(tzinfo=timezone.utc)
                    if t_end.tzinfo is None:
                        t_end = t_end.replace(tzinfo=timezone.utc)
                    hours = (t_end - t_start).total_seconds() / 3600
                    if hours > MAX_SESSION_HOURS:
                        long_sessions.append(sid)
                except (ValueError, TypeError):
                    pass
        if long_sessions:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 5.0
            c.finding = (
                f"PARTIAL: {len(long_sessions)} session(s) exceeded "
                f"{MAX_SESSION_HOURS}-hour maximum: {long_sessions[:3]}"
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: No sessions exceeded {MAX_SESSION_HOURS}-hour limit."
        c.evidence_collected = [
            f"Sessions analyzed: {len(session_durations)}",
            f"Long sessions detected: {len(long_sessions)}",
        ]
        return c

    def _assess_ac_005(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-005: Encryption at rest — 2025 mandatory."""
        phi_actions = [a for a in actions if a.involves_phi]
        if not phi_actions:
            c.status = "compliant"
            c.finding = "No PHI actions in period."
            return c
        unencrypted = [a for a in phi_actions if not a.encryption_at_rest]
        rate = 1.0 - len(unencrypted) / len(phi_actions)
        if unencrypted:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 9.5
            c.finding = (
                f"FAIL: {len(unencrypted)}/{len(phi_actions)} PHI actions ({100*(1-rate):.1f}%) "
                f"lack encryption at rest. Per 2025 HIPAA amendments, this is now a REQUIRED "
                f"safeguard."
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(phi_actions)} PHI actions have encryption_at_rest=True."
        c.evidence_collected = [
            f"PHI actions: {len(phi_actions)}",
            f"Encrypted at rest: {len(phi_actions) - len(unencrypted)}",
            f"Encryption compliance rate: {rate:.1%}",
        ]
        return c

    def _assess_ac_006(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-006: RBAC enforcement — permissions scope check."""
        no_permissions = [a for a in agents if not a.permissions]
        wide_scope = [a for a in agents if a.phi_scope == "organization_wide" and a.risk_tier not in {"critical", "high"}]
        issues = len(no_permissions) + len(wide_scope)
        if issues > 0:
            c.status = "partially_compliant"
            c.severity = "high"
            c.risk_score = 7.0
            c.finding = (
                f"PARTIAL: {len(no_permissions)} agent(s) have no permissions defined; "
                f"{len(wide_scope)} agent(s) have organization_wide scope without critical/high risk tier."
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = "PASS: All agents have permissions defined and scope is appropriately bounded."
        c.evidence_collected = [
            f"Agents with no permissions: {len(no_permissions)}",
            f"Agents with over-scoped phi_scope: {len(wide_scope)}",
        ]
        return c

    def _assess_ac_007(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-007: Minimum necessary — operation-level scope."""
        phi_actions = [a for a in actions if a.involves_phi]
        if not phi_actions:
            c.status = "compliant"
            c.finding = "No PHI actions in period."
            return c
        missing_justification = [a for a in phi_actions if not a.access_justification]
        unrestricted_no_justification = [
            a for a in phi_actions
            if a.minimum_necessary_scope == "unrestricted" and not a.access_justification
        ]
        issues = len(missing_justification)
        rate = 1.0 - issues / len(phi_actions)
        if unrestricted_no_justification:
            c.status = "non_compliant"
            c.severity = "high"
            c.risk_score = 7.5
            c.finding = (
                f"FAIL: {len(unrestricted_no_justification)} PHI action(s) with "
                f"unrestricted scope and no access_justification. §164.502(b) requires "
                f"documented justification for all PHI access."
            )
        elif issues > 0:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 5.0
            c.finding = (
                f"PARTIAL: {issues}/{len(phi_actions)} PHI actions ({100*(1-rate):.1f}%) "
                f"missing access_justification."
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(phi_actions)} PHI actions have access_justification."
        c.evidence_collected = [
            f"PHI actions: {len(phi_actions)}",
            f"Missing justification: {issues}",
            f"Justification capture rate: {rate:.1%}",
        ]
        return c

    def _assess_ac_008(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AC-008: Credential rotation."""
        active_agents = [a for a in agents if a.status == "active"]
        stale = [a for a in active_agents if a.credential_age_days > CREDENTIAL_ROTATION_MAX_DAYS]
        if stale:
            c.status = "non_compliant" if len(stale) / max(len(active_agents), 1) > 0.2 else "partially_compliant"
            c.severity = "high"
            c.risk_score = 7.5
            c.finding = (
                f"{'FAIL' if c.status == 'non_compliant' else 'PARTIAL'}: "
                f"{len(stale)}/{len(active_agents)} active agents have credentials "
                f"not rotated in >{CREDENTIAL_ROTATION_MAX_DAYS} days."
            )
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(active_agents)} active agents have current credentials."
        c.evidence_collected = [
            f"Active agents: {len(active_agents)}",
            f"Agents with stale credentials: {len(stale)}",
        ]
        return c

    def _assess_au_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AU-001: Audit trail completeness — required fields."""
        if not actions:
            c.status = "not_assessed"
            c.finding = "No actions in period."
            return c
        required = ["action_id", "timestamp", "agent_id", "human_authorizer_id", "operation"]
        incomplete = 0
        for a in actions:
            for f in required:
                if not getattr(a, f, None):
                    incomplete += 1
                    break
        rate = 1.0 - incomplete / len(actions)
        if rate < 0.99:
            c.status = "non_compliant" if rate < 0.95 else "partially_compliant"
            c.severity = "critical" if rate < 0.95 else "medium"
            c.risk_score = 9.0 if rate < 0.95 else 5.0
            c.finding = f"{'FAIL' if rate < 0.95 else 'PARTIAL'}: {incomplete}/{len(actions)} actions have incomplete required fields (completeness={rate:.1%})"
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: {len(actions)} actions, completeness rate {rate:.1%}"
        c.evidence_collected = [f"Actions: {len(actions)}", f"Incomplete: {incomplete}", f"Completeness: {rate:.1%}"]
        return c

    def _assess_au_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AU-002: Tamper-evident hash chain verification."""
        valid, errors = self.store.verify_chain_integrity()
        if valid:
            total = self.store.count_actions()
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: Hash chain integrity verified across {total} records. No tampering detected."
        else:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 10.0
            c.finding = f"CRITICAL FAIL: {len(errors)} chain integrity error(s): {errors[:3]}"
        c.evidence_collected = [f"Chain valid: {valid}", f"Errors: {len(errors)}"]
        return c

    def _assess_au_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AU-003: Operation-level granularity."""
        phi_actions = [a for a in actions if a.involves_phi]
        if not phi_actions:
            c.status = "compliant"
            c.finding = "No PHI actions in period."
            return c
        missing_detail = [a for a in phi_actions if not a.operation_detail]
        rate = 1.0 - len(missing_detail) / len(phi_actions)
        if rate < 0.80:
            c.status = "non_compliant"
            c.severity = "high"
            c.risk_score = 7.0
            c.finding = f"FAIL: {len(missing_detail)}/{len(phi_actions)} PHI actions missing operation_detail ({rate:.1%} populated)"
        elif rate < 0.95:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 4.0
            c.finding = f"PARTIAL: operation_detail populated for {rate:.1%} of PHI actions"
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: operation_detail populated for {rate:.1%} of PHI actions"
        c.evidence_collected = [f"PHI actions: {len(phi_actions)}", f"With operation_detail: {len(phi_actions)-len(missing_detail)}"]
        return c

    def _assess_au_004(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AU-004: Real-time anomaly detection (check violations are being generated)."""
        violations = self.store.get_violation_summary()
        total_v = violations.get("total", 0)
        if total_v > 0:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: ViolationDetector active — {total_v} violations detected in period, indicating real-time monitoring is functioning."
        else:
            c.status = "partially_compliant"
            c.severity = "low"
            c.risk_score = 2.0
            c.finding = "PARTIAL: No violations detected. Either the environment is fully compliant, or the ViolationDetector is not running."
        c.evidence_collected = [f"Total violations in period: {total_v}"]
        return c

    def _assess_au_005(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AU-005: Retention policy check."""
        from .config import AUDIT_LOG_RETENTION_DAYS
        if AUDIT_LOG_RETENTION_DAYS >= 2190:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: Retention policy set to {AUDIT_LOG_RETENTION_DAYS} days (≥2190 day / 6-year requirement met)."
        else:
            c.status = "non_compliant"
            c.severity = "high"
            c.risk_score = 7.5
            c.finding = f"FAIL: Retention policy is {AUDIT_LOG_RETENTION_DAYS} days, below the 6-year (2190 day) HIPAA requirement."
        c.evidence_collected = [f"Configured retention: {AUDIT_LOG_RETENTION_DAYS} days"]
        return c

    def _assess_au_006(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """AU-006: Periodic audit log review — check for existing reports."""
        with self.store._session() as session:
            from .models import ComplianceReportORM
            report_count = session.query(ComplianceReportORM).count()
        if report_count > 0:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: {report_count} compliance report(s) on record, indicating regular review."
        else:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 4.0
            c.finding = "PARTIAL: No compliance reports found. Generate and review reports at least quarterly."
        c.evidence_collected = [f"Reports on record: {report_count}"]
        return c

    def _assess_in_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """IN-001: Data modification tracking."""
        modified = [a for a in actions if a.data_modified]
        if not modified:
            c.status = "compliant"
            c.finding = "No modification actions in period."
            return c
        missing_hashes = [a for a in modified if not a.input_hash or not a.output_hash]
        if missing_hashes:
            c.status = "non_compliant" if len(missing_hashes) / len(modified) > 0.1 else "partially_compliant"
            c.severity = "high"
            c.risk_score = 7.5
            c.finding = f"{'FAIL' if c.status == 'non_compliant' else 'PARTIAL'}: {len(missing_hashes)}/{len(modified)} modification actions missing input/output hashes"
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(modified)} modification actions have input and output hashes."
        c.evidence_collected = [f"Modification actions: {len(modified)}", f"Missing hashes: {len(missing_hashes)}"]
        return c

    def _assess_in_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """IN-002: ePHI integrity authentication mechanism."""
        phi_actions = [a for a in actions if a.involves_phi]
        with_hashes = [a for a in phi_actions if a.input_hash and a.output_hash]
        rate = len(with_hashes) / max(len(phi_actions), 1)
        if rate >= 0.90:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: {rate:.1%} of PHI actions have integrity hashes."
        else:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 4.0
            c.finding = f"PARTIAL: Only {rate:.1%} of PHI actions have input/output integrity hashes."
        c.evidence_collected = [f"PHI actions with hashes: {len(with_hashes)}/{len(phi_actions)}"]
        return c

    def _assess_in_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """IN-003: Audit record hash chain validation."""
        return self._assess_au_002(c, actions, agents)  # Same check

    def _assess_pa_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """PA-001: Entity authentication before PHI access."""
        no_auth_method = [a for a in agents if not a.authentication_method]
        if no_auth_method:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 9.5
            c.finding = f"FAIL: {len(no_auth_method)} agent(s) have no authentication_method configured."
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(agents)} agents have authentication_method configured."
        c.evidence_collected = [f"Agents without auth method: {len(no_auth_method)}"]
        return c

    def _assess_pa_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """PA-002: Delegation chain completeness."""
        if not actions:
            c.status = "not_assessed"
            c.finding = "No actions in period."
            return c
        short_chains = [a for a in actions if len(a.delegation_chain) < 2]
        rate = 1.0 - len(short_chains) / len(actions)
        if short_chains:
            c.status = "non_compliant" if rate < 0.95 else "partially_compliant"
            c.severity = "critical" if rate < 0.95 else "high"
            c.risk_score = 9.0 if rate < 0.95 else 7.0
            c.finding = f"{'FAIL' if rate < 0.95 else 'PARTIAL'}: {len(short_chains)}/{len(actions)} actions have incomplete delegation chains (rate={rate:.1%})"
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(actions)} actions have delegation chains ≥2 entries."
        c.evidence_collected = [f"Actions with short chains: {len(short_chains)}", f"Chain completeness: {rate:.1%}"]
        return c

    def _assess_pa_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """PA-003: Authentication method strength for critical/high agents."""
        strong_methods = {"oauth2_client_credentials", "mtls", "saml", "mfa_token"}
        critical_agents = [a for a in agents if a.risk_tier in {"critical", "high"}]
        weak_auth = [a for a in critical_agents if a.authentication_method not in strong_methods]
        if weak_auth:
            c.status = "partially_compliant"
            c.severity = "high"
            c.risk_score = 7.0
            c.finding = f"PARTIAL: {len(weak_auth)} critical/high-tier agent(s) using weak authentication method."
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(critical_agents)} critical/high-tier agents use strong authentication."
        c.evidence_collected = [f"Critical/high agents with weak auth: {len(weak_auth)}"]
        return c

    def _assess_pa_004(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """PA-004: BAA coverage for third-party agents."""
        third_party = [a for a in agents if a.is_third_party]
        no_baa = [a for a in third_party if not a.baa_reference]
        if no_baa:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 9.5
            c.finding = f"FAIL: {len(no_baa)}/{len(third_party)} third-party agents lack a BAA reference: {[a.agent_name for a in no_baa[:3]]}"
        elif not third_party:
            c.status = "compliant"
            c.finding = "No third-party agents registered."
            c.risk_score = 0.0
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(third_party)} third-party agents have BAA references."
        c.evidence_collected = [f"Third-party agents: {len(third_party)}", f"Without BAA: {len(no_baa)}"]
        return c

    def _assess_ts_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """TS-001: Encryption in transit — mandatory per 2025 amendment."""
        phi_actions = [a for a in actions if a.involves_phi]
        if not phi_actions:
            c.status = "compliant"
            c.finding = "No PHI actions in period."
            return c
        unencrypted = [a for a in phi_actions if not a.encryption_in_transit]
        rate = 1.0 - len(unencrypted) / len(phi_actions)
        if unencrypted:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 9.5
            c.finding = f"CRITICAL FAIL: {len(unencrypted)}/{len(phi_actions)} PHI actions ({100*(1-rate):.1f}%) lack encryption in transit. Per 2025 HIPAA amendments, this is now REQUIRED."
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(phi_actions)} PHI actions have encryption_in_transit=True."
        c.evidence_collected = [f"PHI actions: {len(phi_actions)}", f"Unencrypted: {len(unencrypted)}", f"Compliance rate: {rate:.1%}"]
        return c

    def _assess_ts_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """TS-002: FIPS 140-3 validated encryption."""
        phi_actions = [a for a in actions if a.involves_phi]
        if not phi_actions:
            c.status = "compliant"
            c.finding = "No PHI actions in period."
            return c
        fips_validated = [a for a in phi_actions if a.fips_validated]
        rate = len(fips_validated) / len(phi_actions)
        if rate < 0.50:
            c.status = "non_compliant"
            c.severity = "high"
            c.risk_score = 7.5
            c.finding = f"FAIL: Only {rate:.1%} of PHI actions use FIPS 140-3 validated encryption. Per 2025 amendments, FIPS is required."
        elif rate < 0.99:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 4.0
            c.finding = f"PARTIAL: {rate:.1%} of PHI actions use FIPS 140-3 validated encryption."
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: {rate:.1%} of PHI actions use FIPS 140-3 validated modules."
        c.evidence_collected = [f"FIPS rate: {rate:.1%}"]
        return c

    def _assess_ts_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """TS-003: Transmission integrity controls."""
        transmit_actions = [a for a in actions if a.operation == "transmit"]
        if not transmit_actions:
            c.status = "compliant"
            c.finding = "No transmit actions in period."
            return c
        with_output_hash = [a for a in transmit_actions if a.output_hash]
        rate = len(with_output_hash) / len(transmit_actions)
        if rate >= 0.95:
            c.status = "compliant"
            c.finding = f"PASS: {rate:.1%} of transmit actions have output_hash for integrity."
            c.risk_score = 0.0
        else:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 3.5
            c.finding = f"PARTIAL: Only {rate:.1%} of transmit actions have output_hash populated."
        c.evidence_collected = [f"Transmit actions: {len(transmit_actions)}", f"With output hash: {len(with_output_hash)}"]
        return c

    def _assess_ts_004(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """TS-004: Network segmentation — external PHI transmission."""
        external_phi = [
            a for a in actions
            if a.involves_phi and a.network_zone in {"external", "cloud_non_hipaa"}
        ]
        if not external_phi:
            c.status = "compliant"
            c.finding = "No external PHI transmissions in period."
            return c
        unencrypted_external = [a for a in external_phi if not a.encryption_in_transit]
        if unencrypted_external:
            c.status = "non_compliant"
            c.severity = "critical"
            c.risk_score = 10.0
            c.finding = f"CRITICAL FAIL: {len(unencrypted_external)} unencrypted PHI transmissions to external network zone — potential reportable breach."
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: All {len(external_phi)} external PHI transmissions are encrypted."
        c.evidence_collected = [f"External PHI transmissions: {len(external_phi)}", f"Unencrypted: {len(unencrypted_external)}"]
        return c

    def _assess_mn_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """MN-001: Minimum necessary — bulk access."""
        from collections import defaultdict
        session_volume: dict[str, int] = defaultdict(int)
        for a in actions:
            if a.involves_phi:
                session_volume[a.session_id] += a.phi_volume
        bulk_sessions = {sid: vol for sid, vol in session_volume.items() if vol > BULK_ACCESS_THRESHOLD}
        if bulk_sessions:
            c.status = "partially_compliant"
            c.severity = "high"
            c.risk_score = 7.0
            c.finding = f"PARTIAL: {len(bulk_sessions)} session(s) accessed >{BULK_ACCESS_THRESHOLD} patient records. Review for minimum necessary compliance."
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: No sessions exceeded {BULK_ACCESS_THRESHOLD}-record threshold."
        c.evidence_collected = [f"Bulk sessions: {len(bulk_sessions)}"]
        return c

    def _assess_mn_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """MN-002: Access justification capture rate."""
        return self._assess_ac_007(c, actions, agents)

    def _assess_mn_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """MN-003: Scope drift detection."""
        c.status = "partially_compliant"
        c.severity = "low"
        c.risk_score = 2.0
        c.finding = "Manual review required: run ViolationDetector.detect_scope_drift() per agent and review results quarterly."
        c.evidence_collected = ["Automated scope drift analysis should be run via CLI: audit detect-scope-drift"]
        return c

    def _assess_rm_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """RM-001: NIST AI RMF Govern — AI governance coverage."""
        required_fields = ["owner_id", "owner_role", "department", "risk_tier", "phi_scope"]
        fully_governed = [
            a for a in agents
            if all(getattr(a, f, None) for f in required_fields)
        ]
        rate = len(fully_governed) / max(len(agents), 1)
        if rate >= 0.95:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: {rate:.1%} of agents have complete governance metadata."
        elif rate >= 0.75:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 4.0
            c.finding = f"PARTIAL: {rate:.1%} of agents have complete governance metadata."
        else:
            c.status = "non_compliant"
            c.severity = "high"
            c.risk_score = 7.0
            c.finding = f"FAIL: Only {rate:.1%} of agents have complete governance metadata (owner, risk tier, phi scope)."
        c.evidence_collected = [f"Agents with complete governance: {len(fully_governed)}/{len(agents)}"]
        return c

    def _assess_rm_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """RM-002: NIST AI RMF Map — inventory completeness."""
        action_ids = {a.agent_id for a in actions}
        registry_ids = {a.agent_id for a in agents}
        unregistered = action_ids - registry_ids
        if unregistered:
            c.status = "non_compliant"
            c.severity = "high"
            c.risk_score = 8.0
            c.finding = f"FAIL: {len(unregistered)} agent(s) in action log not in registry (shadow agents): {list(unregistered)[:5]}"
        else:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = "PASS: All agents appearing in action logs are registered in the inventory."
        c.evidence_collected = [f"Shadow agents: {len(unregistered)}"]
        return c

    def _assess_rm_003(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """RM-003: NIST AI RMF Measure/Manage — continuous monitoring."""
        return self._assess_au_004(c, actions, agents)

    def _assess_ot_001(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """OT-001: ONC HTI-1 FAVES transparency documentation."""
        applicable = [a for a in agents if a.agent_type in {"decision_support", "diagnostic_imaging"}]
        if not applicable:
            c.status = "compliant"
            c.finding = "No applicable agents (decision_support / diagnostic_imaging) registered."
            return c
        with_faves = [a for a in applicable if "intended_use" in a.tags]
        rate = len(with_faves) / len(applicable)
        if rate >= 0.90:
            c.status = "compliant"
            c.severity = "informational"
            c.risk_score = 0.0
            c.finding = f"PASS: {rate:.1%} of applicable agents have ONC HTI-1 FAVES documentation."
        else:
            c.status = "partially_compliant"
            c.severity = "medium"
            c.risk_score = 3.0
            c.finding = f"PARTIAL: Only {rate:.1%} of decision_support/diagnostic_imaging agents have intended_use in tags."
        c.evidence_collected = [f"Applicable agents: {len(applicable)}", f"With FAVES: {len(with_faves)}"]
        return c

    def _assess_ot_002(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """OT-002: FDA ALCOA+ compliance."""
        return self._assess_au_001(c, actions, agents)

    def _assess_generic(self, c: ComplianceControl, actions: list[AgentAction], agents: list[AgentIdentity]) -> ComplianceControl:
        """Fallback assessment for controls without a specific implementation."""
        c.status = "not_assessed"
        c.finding = "No automated assessment available. Manual review required."
        c.evidence_collected = ["Manual assessment required"]
        return c

    # ------------------------------------------------------------------
    # Scoring and analysis
    # ------------------------------------------------------------------

    def compute_compliance_score(self, results: list[ComplianceControl]) -> float:
        """
        Compute a weighted compliance score from 0–100.

        Required controls are weighted 2x (REQUIRED_CONTROL_WEIGHT).
        Addressable controls are weighted 1x (ADDRESSABLE_CONTROL_WEIGHT).
        Not-assessed controls are excluded from the denominator.

        Scoring per control:
          compliant            → full weight
          partially_compliant  → 0.5 × weight
          non_compliant        → 0 × weight

        Returns:
            Compliance score 0.0–100.0
        """
        from .config import COMPLIANT_SCORE, PARTIALLY_COMPLIANT_SCORE, NON_COMPLIANT_SCORE

        total_weight = 0.0
        earned_weight = 0.0

        for r in results:
            if r.status == "not_assessed":
                continue
            weight = r.weight
            total_weight += weight
            if r.status == "compliant":
                earned_weight += weight * COMPLIANT_SCORE
            elif r.status == "partially_compliant":
                earned_weight += weight * PARTIALLY_COMPLIANT_SCORE
            # non_compliant earns 0

        if total_weight == 0:
            return 0.0
        return round((earned_weight / total_weight) * 100, 2)

    def get_rating(self, score: float) -> str:
        """Map numeric score to rating label."""
        if score >= RATING_COMPLIANT_THRESHOLD:
            return "Compliant"
        elif score >= RATING_SUBSTANTIAL_THRESHOLD:
            return "Substantially Compliant"
        elif score >= RATING_PARTIAL_THRESHOLD:
            return "Partially Compliant"
        elif score >= RATING_CRITICAL_THRESHOLD:
            return "Non-Compliant"
        else:
            return "Critical — Immediate Action Required"

    def generate_gap_analysis(self, results: list[ComplianceControl]) -> list[dict]:
        """
        Generate a prioritized gap analysis from assessment results.

        Returns a list of gap items sorted by severity (critical first),
        each with remediation steps and HIPAA reference.

        Returns:
            List of gap dicts, priority-ordered.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        gaps = [
            r for r in results
            if r.status in {"non_compliant", "partially_compliant"}
        ]
        gaps.sort(key=lambda r: (severity_order.get(r.severity, 5), -r.risk_score))

        return [
            {
                "priority": i + 1,
                "control_id": g.control_id,
                "hipaa_section": g.hipaa_section,
                "standard": g.hipaa_standard,
                "status": g.status,
                "severity": g.severity,
                "risk_score": g.risk_score,
                "finding": g.finding,
                "remediation": g.remediation or f"Review {g.hipaa_section} and implement: {g.description}",
                "requirement_type": g.requirement_type,
                "nist_csf": g.nist_csf_mapping,
                "nist_800_53": g.nist_800_53_mapping,
            }
            for i, g in enumerate(gaps)
        ]

    def map_to_nist_csf(self, results: list[ComplianceControl]) -> dict:
        """
        Map assessment results to NIST CSF categories.

        Returns dict of CSF function → average score (0.0–1.0).
        """
        csf_scores: dict[str, list[float]] = {}
        for r in results:
            if not r.nist_csf_mapping or r.status == "not_assessed":
                continue
            prefix = r.nist_csf_mapping.split(".")[0]  # "PR", "DE", "ID", "RS", "RC"
            score = (
                1.0 if r.status == "compliant"
                else 0.5 if r.status == "partially_compliant"
                else 0.0
            )
            csf_scores.setdefault(prefix, []).append(score)
        return {k: round(sum(v) / len(v), 3) for k, v in csf_scores.items()}

    def map_to_nist_ai_rmf(self, results: list[ComplianceControl]) -> dict:
        """
        Map assessment results to NIST AI RMF functions.

        Returns dict of function → score (0.0–1.0):
          {"govern": 0.8, "map": 1.0, "measure": 0.7, "manage": 0.6}
        """
        rmf_scores: dict[str, list[float]] = {}
        for r in results:
            func = r.nist_ai_rmf_function.lower() if r.nist_ai_rmf_function else ""
            if not func or r.status == "not_assessed":
                continue
            score = (
                1.0 if r.status == "compliant"
                else 0.5 if r.status == "partially_compliant"
                else 0.0
            )
            rmf_scores.setdefault(func, []).append(score)
        return {k: round(sum(v) / len(v), 3) for k, v in rmf_scores.items()}

    def build_report(
        self,
        results: list[ComplianceControl],
        period_start: str,
        period_end: str,
        org_name: str,
    ) -> ComplianceReport:
        """
        Assemble a full ComplianceReport from assessment results.

        Args:
            results: List of assessed ComplianceControl objects.
            period_start: ISO 8601 period start.
            period_end:   ISO 8601 period end.
            org_name:     Organization name.

        Returns:
            Populated ComplianceReport dataclass.
        """
        score = self.compute_compliance_score(results)
        rating = self.get_rating(score)
        gap_analysis = self.generate_gap_analysis(results)
        nist_rmf = self.map_to_nist_ai_rmf(results)

        agents = self.store.list_agents()
        actions = self.store.query_actions(start=period_start, end=period_end)
        violation_summary = self.store.get_violation_summary(start=period_start, end=period_end)

        by_risk_tier: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for a in agents:
            by_risk_tier[a.risk_tier] = by_risk_tier.get(a.risk_tier, 0) + 1
            by_status[a.status] = by_status.get(a.status, 0) + 1

        by_operation: dict[str, int] = {}
        by_phi_cat: dict[str, int] = {}
        total_phi = 0
        for a in actions:
            by_operation[a.operation] = by_operation.get(a.operation, 0) + 1
            for cat in a.phi_categories:
                by_phi_cat[cat] = by_phi_cat.get(cat, 0) + 1
            total_phi += a.phi_volume

        # Build top risks from gap analysis
        top_risks = [
            {
                "rank": g["priority"],
                "description": g["finding"],
                "hipaa_section": g["hipaa_section"],
                "severity": g["severity"],
                "risk_score": g["risk_score"],
            }
            for g in gap_analysis[:5]
        ]

        # Prioritized recommendations
        recommendations = [
            {
                "priority": g["priority"],
                "title": g["standard"],
                "description": g["remediation"],
                "hipaa_ref": g["hipaa_section"],
                "effort": "high" if g["severity"] in {"critical"} else "medium" if g["severity"] == "high" else "low",
                "severity": g["severity"],
            }
            for g in gap_analysis[:10]
        ]

        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=_utc_now(),
            report_period_start=period_start,
            report_period_end=period_end,
            organization_name=org_name,
            overall_score=score,
            overall_rating=rating,
            total_agents=len(agents),
            agents_by_risk_tier=by_risk_tier,
            agents_by_status=by_status,
            total_actions=len(actions),
            actions_by_operation=by_operation,
            actions_by_phi_category=by_phi_cat,
            phi_records_accessed=total_phi,
            controls_assessed=sum(1 for r in results if r.status != "not_assessed"),
            controls_compliant=sum(1 for r in results if r.status == "compliant"),
            controls_non_compliant=sum(1 for r in results if r.status == "non_compliant"),
            controls_partially_compliant=sum(1 for r in results if r.status == "partially_compliant"),
            total_violations=violation_summary.get("total", 0),
            violations_by_severity=violation_summary.get("by_severity", {}),
            violations_by_type=violation_summary.get("by_type", {}),
            open_violations=violation_summary.get("by_status", {}).get("open", 0),
            remediated_violations=violation_summary.get("by_status", {}).get("remediated", 0),
            top_risks=top_risks,
            nist_ai_rmf_scores=nist_rmf,
            recommendations=recommendations,
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
