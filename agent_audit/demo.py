#!/usr/bin/env python3
"""
Demo mode with realistic healthcare AI scenarios.

Populates the audit database with representative agents and actions drawn from
real-world healthcare AI use cases. Designed to showcase the full capabilities
of the compliance engine with an illustrative but realistic dataset.

Scenarios included:
  1. Clinical Documentation Agent (Epic DAX-style) — nominal operation
  2. Prior Authorization Agent — bulk access pattern (V-005)
  3. Clinical Decision Support Agent — after-hours access (V-016)
  4. Medical Coding Agent — stale credentials (V-007)
  5. Shadow/Unregistered Agent — security incident (V-015)
  6. Triage Chatbot — missing BAA for third-party vendor (V-008)
  7. Radiology AI — FIPS encryption gap (V-011)
  8. Discharge Summary Agent — nominal with complete compliance

Usage::

    python -m agent_audit.demo
    # or via CLI:
    audit demo --seed 42
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .config import DB_PATH
from .ingestion import ActionIngester
from .models import AgentAction, AgentIdentity
from .storage import AuditStore
from .violations import ViolationDetector


# ---------------------------------------------------------------------------
# Demo Agent Definitions
# ---------------------------------------------------------------------------

def _ts(days_ago: float = 0, hours_ago: float = 0, minutes_ago: float = 0) -> str:
    """Return ISO 8601 timestamp offset from now."""
    delta = timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
    return (datetime.now(timezone.utc) - delta).isoformat()


DEMO_AGENTS: list[AgentIdentity] = [

    AgentIdentity(
        agent_id="agent-dax-001",
        agent_name="Clinical Documentation Assistant v2.3 (DAX)",
        agent_type="clinical_documentation",
        vendor="Nuance/DAX",
        model_type="llm",
        model_version="nuance-dax-v2.3",
        deployment_env="production",
        owner_id="EMP-10042",
        owner_role="CMIO",
        department="Primary Care",
        registered_at=_ts(days_ago=180),
        last_authenticated=_ts(hours_ago=2),
        status="active",
        risk_tier="high",
        phi_scope="patient_record",
        permissions=["read_patient_summary", "read_encounter_notes", "write_clinical_note"],
        baa_reference="BAA-2024-NUANCE-001",
        authentication_method="oauth2_client_credentials",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=45),
        tags={
            "intended_use": "Ambient clinical documentation via voice",
            "cautioned_uses": "Not for diagnosis or treatment decisions",
            "faves_assessment_url": "https://internal.example.com/faves/dax-001",
        },
    ),

    AgentIdentity(
        agent_id="agent-prior-auth-002",
        agent_name="Prior Authorization Automation v1.4",
        agent_type="prior_auth",
        vendor="Custom",
        model_type="hybrid",
        model_version="internal-pa-v1.4",
        deployment_env="production",
        owner_id="EMP-20031",
        owner_role="Revenue Cycle Director",
        department="Revenue Cycle",
        registered_at=_ts(days_ago=90),
        last_authenticated=_ts(hours_ago=6),
        status="active",
        risk_tier="high",
        phi_scope="patient_record",
        permissions=["read_patient_summary", "read_insurance", "read_medications", "write_auth_request"],
        baa_reference="",  # MISSING BAA — triggers V-008
        authentication_method="api_key",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=95),  # STALE — triggers V-007
        tags={"cost_center": "RC-001"},
    ),

    AgentIdentity(
        agent_id="agent-cds-003",
        agent_name="Sepsis Early Warning System v3.1",
        agent_type="decision_support",
        vendor="Custom",
        model_type="ml_classifier",
        model_version="sepsis-lgbm-v3.1",
        deployment_env="production",
        owner_id="EMP-30011",
        owner_role="IT Director",
        department="Emergency",
        registered_at=_ts(days_ago=365),
        last_authenticated=_ts(hours_ago=1),
        status="active",
        risk_tier="critical",
        phi_scope="department_wide",
        permissions=["read_vitals", "read_lab_values", "read_medications", "write_alert"],
        baa_reference="",  # Internal — no BAA needed
        authentication_method="mtls",
        credential_rotation_days=30,
        last_credential_rotation=_ts(days_ago=28),
        tags={
            "intended_use": "Early detection of sepsis in ED patients",
            "demographic_representativeness": "Validated on 50k patients, 55% male, 32% non-white",
        },
    ),

    AgentIdentity(
        agent_id="agent-coding-004",
        agent_name="Medical Coding Assistant v2.0",
        agent_type="coding",
        vendor="3M",
        model_type="llm",
        model_version="3m-cdi-v2.0",
        deployment_env="production",
        owner_id="EMP-20044",
        owner_role="HIM Director",
        department="Health Information Management",
        registered_at=_ts(days_ago=200),
        last_authenticated=_ts(hours_ago=8),
        status="active",
        risk_tier="medium",
        phi_scope="patient_record",
        permissions=["read_clinical_note", "read_diagnosis", "read_procedures", "write_coding_suggestion"],
        baa_reference="BAA-2024-3M-002",
        authentication_method="saml",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=100),  # STALE — triggers V-007
        tags={},
    ),

    AgentIdentity(
        agent_id="agent-radiology-005",
        agent_name="Radiology AI Triage v1.2 (Aidoc)",
        agent_type="diagnostic_imaging",
        vendor="Aidoc",
        model_type="ml_classifier",
        model_version="aidoc-cxr-v1.2",
        deployment_env="production",
        owner_id="EMP-40022",
        owner_role="Radiology Director",
        department="Radiology",
        registered_at=_ts(days_ago=120),
        last_authenticated=_ts(hours_ago=3),
        status="active",
        risk_tier="high",
        phi_scope="patient_record",
        permissions=["read_imaging", "write_alert", "read_patient_summary"],
        baa_reference="BAA-2024-AIDOC-003",
        authentication_method="oauth2_client_credentials",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=60),
        tags={
            "intended_use": "Triage prioritization for chest X-rays",
            "fda_class": "II",
            "cautioned_uses": "Not a standalone diagnostic device",
        },
    ),

    AgentIdentity(
        agent_id="agent-chatbot-006",
        agent_name="Patient Triage Chatbot v1.0 (Orbita)",
        agent_type="chatbot",
        vendor="Orbita",
        model_type="llm",
        model_version="orbita-triage-v1.0",
        deployment_env="production",
        owner_id="EMP-50001",
        owner_role="Patient Experience Director",
        department="Patient Services",
        registered_at=_ts(days_ago=60),
        last_authenticated=_ts(hours_ago=4),
        status="active",
        risk_tier="high",
        phi_scope="individual_encounter",
        permissions=["read_patient_summary", "write_triage_note"],
        baa_reference="BAA-2024-ORBITA-004",
        authentication_method="oauth2_client_credentials",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=30),
        tags={},
    ),

    AgentIdentity(
        agent_id="agent-discharge-007",
        agent_name="Discharge Summary Generator v1.5 (Abridge)",
        agent_type="clinical_documentation",
        vendor="Abridge",
        model_type="llm",
        model_version="abridge-ds-v1.5",
        deployment_env="production",
        owner_id="EMP-10042",
        owner_role="CMIO",
        department="Hospitalist",
        registered_at=_ts(days_ago=150),
        last_authenticated=_ts(hours_ago=1),
        status="active",
        risk_tier="high",
        phi_scope="patient_record",
        permissions=["read_patient_summary", "read_encounter_notes", "read_medications", "read_lab_values", "write_clinical_note"],
        baa_reference="BAA-2024-ABRIDGE-005",
        authentication_method="oauth2_client_credentials",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=30),
        tags={
            "intended_use": "Automated discharge summary generation",
            "cautioned_uses": "Requires physician review before finalization",
        },
    ),

    AgentIdentity(
        agent_id="agent-research-008",
        agent_name="Clinical Research Query Agent v1.0",
        agent_type="research",
        vendor="Custom",
        model_type="rule_engine",
        model_version="research-query-v1.0",
        deployment_env="staging",
        owner_id="EMP-60003",
        owner_role="Research Director",
        department="Research",
        registered_at=_ts(days_ago=30),
        last_authenticated=_ts(days_ago=5),
        status="under_review",  # Under review — accessing PHI triggers V-017
        risk_tier="medium",
        phi_scope="organization_wide",
        permissions=["read_de_identified", "query_cohort"],
        baa_reference="",
        authentication_method="api_key",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=25),
        tags={},
    ),
]


# ---------------------------------------------------------------------------
# Demo Action Generation
# ---------------------------------------------------------------------------

def generate_demo_actions(
    agents: list[AgentIdentity],
    rng: random.Random,
    n_days: int = 7,
) -> list[AgentAction]:
    """
    Generate a realistic set of demo AgentAction records.

    Covers both nominal (compliant) and anomalous (violation-triggering) scenarios.
    """
    actions: list[AgentAction] = []
    ingester = ActionIngester()

    # ----------------------------------------------------------------
    # Agent 1: DAX — Nominal clinical documentation (compliant)
    # ----------------------------------------------------------------
    dax = agents[0]
    for day in range(n_days):
        for encounter_num in range(rng.randint(8, 15)):
            session_id = str(uuid.uuid4())
            wf_id = f"encounter_{uuid.uuid4().hex[:8]}"
            patient_mrn = f"MRN-{rng.randint(100000, 999999)}"
            ts_offset = timedelta(days=n_days - day - 1, hours=rng.uniform(8, 17))
            base_ts = (datetime.now(timezone.utc) - ts_offset).isoformat()

            # Step 1: Read encounter note
            actions.append(ingester.ingest_action({
                "action_id": str(uuid.uuid4()),
                "timestamp": base_ts,
                "agent_id": dax.agent_id,
                "session_id": session_id,
                "workflow_id": wf_id,
                "human_authorizer_id": f"DR-{rng.randint(1000, 9999)}",
                "human_authorizer_role": "Attending Physician",
                "delegation_chain": [f"Dr. Smith (NPI: {rng.randint(1000000000, 9999999999)})", "Epic Workflow Engine v3.2", dax.agent_name],
                "operation": "read",
                "operation_detail": f"Read encounter notes for patient {patient_mrn} to generate clinical documentation",
                "resource_type": "patient_record",
                "resource_id": patient_mrn,
                "phi_categories": ["demographics", "diagnosis", "medications", "vitals"],
                "phi_volume": 1,
                "data_classification": "phi",
                "source_system": "Epic EHR",
                "target_system": "DAX Clinical Documentation Module",
                "network_zone": "internal_clinical",
                "access_justification": f"Generating clinical note for encounter {wf_id}",
                "minimum_necessary_scope": "encounter_specific",
                "policy_applied": "CLINICAL_DOC_ACCESS_POLICY_v2",
                "encryption_in_transit": True,
                "encryption_at_rest": True,
                "encryption_algorithm": "AES-256-GCM",
                "fips_validated": True,
                "input_hash": uuid.uuid4().hex + uuid.uuid4().hex,
                "output_hash": uuid.uuid4().hex + uuid.uuid4().hex,
                "data_modified": False,
                "modification_type": "none",
                "status": "completed",
                "duration_ms": rng.randint(200, 1500),
            }))

            # Step 2: Write clinical note
            ts_write = (datetime.fromisoformat(base_ts) + timedelta(seconds=rng.randint(30, 120))).isoformat()
            actions.append(ingester.ingest_action({
                "action_id": str(uuid.uuid4()),
                "timestamp": ts_write,
                "agent_id": dax.agent_id,
                "session_id": session_id,
                "workflow_id": wf_id,
                "human_authorizer_id": f"DR-{rng.randint(1000, 9999)}",
                "human_authorizer_role": "Attending Physician",
                "delegation_chain": ["Dr. Smith", "Epic Workflow Engine", dax.agent_name],
                "operation": "write",
                "operation_detail": f"Write AI-generated clinical note for encounter {wf_id}",
                "resource_type": "clinical_note",
                "resource_id": f"NOTE-{uuid.uuid4().hex[:8]}",
                "phi_categories": ["demographics", "diagnosis", "medications"],
                "phi_volume": 1,
                "data_classification": "phi",
                "source_system": "DAX Clinical Documentation Module",
                "target_system": "Epic EHR",
                "network_zone": "internal_clinical",
                "access_justification": f"Submitting completed clinical note for encounter {wf_id}",
                "minimum_necessary_scope": "encounter_specific",
                "policy_applied": "CLINICAL_DOC_WRITE_POLICY_v2",
                "encryption_in_transit": True,
                "encryption_at_rest": True,
                "encryption_algorithm": "AES-256-GCM",
                "fips_validated": True,
                "input_hash": uuid.uuid4().hex * 2,
                "output_hash": uuid.uuid4().hex * 2,
                "data_modified": True,
                "modification_type": "creation",
                "status": "completed",
                "duration_ms": rng.randint(100, 500),
            }))

    # ----------------------------------------------------------------
    # Agent 2: Prior Auth — Bulk access (V-005) + Stale credentials (V-007)
    # ----------------------------------------------------------------
    pa = agents[1]
    session_id = str(uuid.uuid4())
    # Bulk access: >100 records in one session
    for i in range(140):
        ts_offset = timedelta(days=1, hours=rng.uniform(9, 16), minutes=i * 0.2)
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - ts_offset).isoformat(),
            "agent_id": pa.agent_id,
            "session_id": session_id,
            "workflow_id": f"pa_batch_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": "EMP-20031",
            "human_authorizer_role": "Revenue Cycle Director",
            "delegation_chain": ["Revenue Cycle Director", "PA Automation System", pa.agent_name],
            "operation": "read",
            "operation_detail": f"Read patient insurance and medication data for prior authorization batch #{i+1}",
            "resource_type": "patient_record",
            "resource_id": f"MRN-{rng.randint(100000, 999999)}",
            "phi_categories": ["insurance", "medications", "diagnosis", "demographics"],
            "phi_volume": 1,
            "data_classification": "phi",
            "source_system": "Epic EHR",
            "target_system": "Prior Auth Processing System",
            "network_zone": "internal_clinical",
            "access_justification": "Automated prior authorization batch processing",
            "minimum_necessary_scope": "unrestricted",  # Triggers V-006
            "policy_applied": "PA_BATCH_ACCESS_POLICY",
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "encryption_algorithm": "AES-256-GCM",
            "fips_validated": False,  # Triggers V-011
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(100, 400),
        }))

    # ----------------------------------------------------------------
    # Agent 3: Sepsis CDS — After-hours access (V-016) + unencrypted action (V-001)
    # ----------------------------------------------------------------
    cds = agents[2]
    # Legitimate 24/7 operation (some after-hours triggers V-016)
    for hour_offset in [0, 3, 6, 10, 14, 17, 22, 25]:  # Some in after-hours
        session_id_cds = str(uuid.uuid4())
        ts = (datetime.now(timezone.utc) - timedelta(hours=hour_offset)).isoformat()
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": ts,
            "agent_id": cds.agent_id,
            "session_id": session_id_cds,
            "workflow_id": f"sepsis_eval_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": f"RN-{rng.randint(1000, 9999)}",
            "human_authorizer_role": "Charge RN",
            "delegation_chain": ["Charge Nurse", "ED Workflow System", cds.agent_name],
            "operation": "read",
            "operation_detail": "Query vitals, labs, and medications for sepsis risk scoring",
            "resource_type": "patient_record",
            "resource_id": f"MRN-{rng.randint(100000, 999999)}",
            "phi_categories": ["vitals", "lab_values", "medications"],
            "phi_volume": 1,
            "data_classification": "phi",
            "source_system": "Epic EHR",
            "target_system": "Sepsis Early Warning System",
            "network_zone": "internal_clinical",
            "access_justification": "Continuous sepsis risk assessment for ED patients",
            "minimum_necessary_scope": "patient_specific",
            "policy_applied": "SEPSIS_MONITORING_POLICY",
            "encryption_in_transit": hour_offset != 3,  # One unencrypted → V-001
            "encryption_at_rest": True,
            "encryption_algorithm": "AES-256-GCM" if hour_offset != 3 else "none",
            "fips_validated": True,
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(50, 200),
        }))

    # ----------------------------------------------------------------
    # Agent 4: Medical Coding — Normal operation, stale creds handled at agent level
    # ----------------------------------------------------------------
    coding = agents[3]
    for i in range(20):
        ts_offset = timedelta(hours=rng.uniform(1, 48))
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - ts_offset).isoformat(),
            "agent_id": coding.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": f"coding_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": f"CODER-{rng.randint(100, 999)}",
            "human_authorizer_role": "Medical Coder",
            "delegation_chain": ["Medical Coder", "HIM Workflow System", coding.agent_name],
            "operation": "read",
            "operation_detail": "Read clinical note for ICD-10 coding suggestion",
            "resource_type": "clinical_note",
            "resource_id": f"NOTE-{uuid.uuid4().hex[:8]}",
            "phi_categories": ["diagnosis", "procedures"],
            "phi_volume": 1,
            "data_classification": "phi",
            "source_system": "Epic EHR",
            "target_system": "3M CDI Module",
            "network_zone": "internal_clinical",
            "access_justification": "ICD-10 and CPT coding for submitted encounter",
            "minimum_necessary_scope": "encounter_specific",
            "policy_applied": "CODING_ACCESS_POLICY",
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "encryption_algorithm": "AES-256-GCM",
            "fips_validated": True,
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(300, 2000),
        }))

    # ----------------------------------------------------------------
    # Agent 5: Radiology AI — FIPS gap (V-011), external transmission
    # ----------------------------------------------------------------
    rad = agents[4]
    for i in range(25):
        ts_offset = timedelta(hours=rng.uniform(1, 72))
        # One external transmission without FIPS → V-003 + V-011
        external = i == 10
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - ts_offset).isoformat(),
            "agent_id": rad.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": f"rad_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": f"RAD-{rng.randint(100, 999)}",
            "human_authorizer_role": "Radiologist",
            "delegation_chain": ["Radiologist", "PACS Workflow", rad.agent_name],
            "operation": "classify",
            "operation_detail": "AI triage classification of chest X-ray for acute findings",
            "resource_type": "radiology_report",
            "resource_id": f"IMG-{uuid.uuid4().hex[:8]}",
            "phi_categories": ["imaging", "demographics"],
            "phi_volume": 1,
            "data_classification": "phi",
            "source_system": "PACS",
            "target_system": "Aidoc Triage Platform" if not external else "External Reporting API",
            "network_zone": "internal_clinical" if not external else "external",
            "access_justification": "AI triage prioritization for emergency radiology workflow",
            "minimum_necessary_scope": "encounter_specific",
            "policy_applied": "RADIOLOGY_AI_POLICY",
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "encryption_algorithm": "AES-256-GCM",
            "fips_validated": False,  # V-011 for all; V-003 for external
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(1000, 5000),
        }))

    # ----------------------------------------------------------------
    # Agent 6: Triage Chatbot — Missing delegation chain (V-014)
    # ----------------------------------------------------------------
    chatbot = agents[5]
    for i in range(15):
        ts_offset = timedelta(hours=rng.uniform(1, 48))
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - ts_offset).isoformat(),
            "agent_id": chatbot.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": f"triage_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": f"PATIENT-{rng.randint(10000, 99999)}",
            "human_authorizer_role": "Patient (Self-Service)",
            "delegation_chain": [chatbot.agent_name] if i < 5 else ["Patient Portal Auth", chatbot.agent_name],  # Some incomplete
            "operation": "read",
            "operation_detail": "Access patient summary for symptom triage intake",
            "resource_type": "patient_record",
            "resource_id": f"MRN-{rng.randint(100000, 999999)}",
            "phi_categories": ["demographics", "medications"],
            "phi_volume": 1,
            "data_classification": "phi",
            "source_system": "Patient Portal",
            "target_system": "Orbita Triage Chatbot",
            "network_zone": "dmz",
            "access_justification": "Patient-initiated triage intake via patient portal",
            "minimum_necessary_scope": "patient_specific",
            "policy_applied": "PATIENT_SELF_SERVICE_POLICY",
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "encryption_algorithm": "TLS-1.3",
            "fips_validated": False,
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(500, 3000),
        }))

    # ----------------------------------------------------------------
    # Agent 7: Discharge Summary — Fully compliant nominal operations
    # ----------------------------------------------------------------
    discharge = agents[6]
    for i in range(12):
        session_id_ds = str(uuid.uuid4())
        ts_offset = timedelta(days=rng.uniform(0, 3), hours=rng.uniform(8, 17))
        ts_base = (datetime.now(timezone.utc) - ts_offset).isoformat()
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": ts_base,
            "agent_id": discharge.agent_id,
            "session_id": session_id_ds,
            "workflow_id": f"discharge_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": f"HOSP-{rng.randint(100, 999)}",
            "human_authorizer_role": "Hospitalist",
            "delegation_chain": [f"Dr. Johnson (NPI: {rng.randint(1000000000, 9999999999)})", "Abridge Integration Service", discharge.agent_name],
            "operation": "summarize",
            "operation_detail": "Generate AI-assisted discharge summary from encounter record",
            "resource_type": "patient_record",
            "resource_id": f"MRN-{rng.randint(100000, 999999)}",
            "phi_categories": ["demographics", "diagnosis", "medications", "procedures", "lab_values"],
            "phi_volume": 1,
            "data_classification": "phi",
            "source_system": "Epic EHR",
            "target_system": "Abridge Discharge Summary Module",
            "network_zone": "internal_clinical",
            "access_justification": f"Generating discharge summary for hospitalized patient encounter {i+1}",
            "minimum_necessary_scope": "encounter_specific",
            "policy_applied": "DISCHARGE_SUMMARY_POLICY",
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "encryption_algorithm": "AES-256-GCM",
            "fips_validated": True,
            "input_hash": uuid.uuid4().hex * 2,
            "output_hash": uuid.uuid4().hex * 2,
            "data_modified": True,
            "modification_type": "summarization",
            "status": "completed",
            "duration_ms": rng.randint(1500, 8000),
        }))

    # ----------------------------------------------------------------
    # Agent 8: Research Agent (under_review) — Deprecated still active (V-017)
    # ----------------------------------------------------------------
    research = agents[7]
    for i in range(5):
        ts_offset = timedelta(hours=rng.uniform(0, 24))
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - ts_offset).isoformat(),
            "agent_id": research.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": f"research_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": "EMP-60003",
            "human_authorizer_role": "Research Director",
            "delegation_chain": ["Research Director", research.agent_name],
            "operation": "query",
            "operation_detail": "Cohort query for research protocol IRB-2024-042",
            "resource_type": "patient_record",
            "resource_id": f"COHORT-{i+1}",
            "phi_categories": ["diagnosis", "lab_values", "demographics"],
            "phi_volume": rng.randint(50, 200),
            "data_classification": "limited_dataset",
            "source_system": "Research Data Warehouse",
            "target_system": "Research Analysis Platform",
            "network_zone": "internal_clinical",
            "access_justification": "Approved IRB protocol IRB-2024-042 cohort analysis",
            "minimum_necessary_scope": "department_wide",
            "policy_applied": "RESEARCH_ACCESS_POLICY",
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "encryption_algorithm": "AES-256-GCM",
            "fips_validated": True,
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(5000, 35000),  # Some >30s → V-019
        }))

    # ----------------------------------------------------------------
    # Shadow Agent: Unregistered agent generating actions (V-015)
    # ----------------------------------------------------------------
    shadow_id = "shadow-agent-UNREGISTERED-x9z"
    for i in range(3):
        ts_offset = timedelta(hours=rng.uniform(1, 12))
        actions.append(ingester.ingest_action({
            "action_id": str(uuid.uuid4()),
            "timestamp": (datetime.now(timezone.utc) - ts_offset).isoformat(),
            "agent_id": shadow_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": f"unknown_wf_{uuid.uuid4().hex[:8]}",
            "human_authorizer_id": "UNKNOWN",
            "human_authorizer_role": "Unknown",
            "delegation_chain": [shadow_id],
            "operation": "read",
            "operation_detail": "",
            "resource_type": "patient_record",
            "resource_id": f"MRN-{rng.randint(100000, 999999)}",
            "phi_categories": ["demographics", "diagnosis"],
            "phi_volume": rng.randint(1, 5),
            "data_classification": "phi",
            "source_system": "Unknown System",
            "target_system": "Unknown Target",
            "network_zone": "internal_clinical",
            "access_justification": "",
            "minimum_necessary_scope": "unrestricted",
            "policy_applied": "",
            "encryption_in_transit": False,  # V-001
            "encryption_at_rest": False,
            "encryption_algorithm": "none",
            "fips_validated": False,
            "data_modified": False,
            "status": "completed",
            "duration_ms": rng.randint(100, 500),
        }))

    return actions


# ---------------------------------------------------------------------------
# Main demo runner
# ---------------------------------------------------------------------------

def run_demo(
    db_path: Optional[Path] = None,
    seed: int = 42,
    verbose: bool = True,
) -> tuple[AuditStore, list[ViolationRecord]]:
    """
    Populate the audit database with demo data and run violation detection.

    Args:
        db_path: Database path (defaults to config.DB_PATH).
        seed:    Random seed for reproducibility.
        verbose: If True, print progress messages.

    Returns:
        Tuple of (AuditStore, list of detected ViolationRecords).
    """
    rng = random.Random(seed)

    def log(msg: str) -> None:
        if verbose:
            print(msg)

    log("\n╔══════════════════════════════════════════════════════════╗")
    log("║   AI AGENT AUDIT TRAIL — DEMO MODE                       ║")
    log("║   HIPAA §164.312 | NIST AI RMF | 2025 Amendments         ║")
    log("╚══════════════════════════════════════════════════════════╝\n")

    # Initialize store
    db = Path(db_path) if db_path else DB_PATH
    store = AuditStore(db_path=db)
    log(f"[+] Database: {db}")

    # Register agents
    log(f"\n[+] Registering {len(DEMO_AGENTS)} demo agents...")
    for agent in DEMO_AGENTS:
        store.store_agent(agent)
        log(f"    ├─ {agent.agent_name} [{agent.risk_tier}] ({agent.status})")

    # Generate and store actions
    log("\n[+] Generating demo actions (7-day period)...")
    actions = generate_demo_actions(DEMO_AGENTS, rng, n_days=7)
    log(f"    ├─ Generated {len(actions)} action records")

    stored = store.store_actions_batch(actions)
    log(f"    └─ Stored {len(stored)} records in tamper-evident chain")

    # Verify chain integrity
    log("\n[+] Verifying hash chain integrity...")
    valid, errors = store.verify_chain_integrity()
    if valid:
        log(f"    └─ ✓ Chain VERIFIED: {len(actions)} records, no tampering")
    else:
        log(f"    └─ ✗ Chain ERRORS: {errors}")

    # Run violation detection
    log("\n[+] Running violation detection engine...")
    detector = ViolationDetector(store=store)
    detector.refresh_known_agents()
    violations = detector.analyze_batch(actions, agents=DEMO_AGENTS)
    shadow_violations = detector.detect_shadow_agents()
    violations.extend(shadow_violations)

    # Also run per-agent checks
    for agent in DEMO_AGENTS:
        agent_violations = detector.analyze_agent(agent)
        violations.extend(agent_violations)

    # Store violations
    for v in violations:
        try:
            store.store_violation(v)
        except Exception:
            pass  # Dedup: some violations may already be stored

    # Summarize violations
    by_sev: dict[str, int] = {}
    for v in violations:
        by_sev[v.severity] = by_sev.get(v.severity, 0) + 1

    log(f"\n[+] Detected {len(violations)} violations:")
    for sev in ["critical", "high", "medium", "low"]:
        count = by_sev.get(sev, 0)
        if count > 0:
            log(f"    {'├' if sev != 'low' else '└'}─ {sev.upper()}: {count}")

    # Show a sample of critical findings
    critical = [v for v in violations if v.severity == "critical"]
    if critical:
        log("\n[+] Critical findings:")
        for v in critical[:5]:
            log(f"    ├─ [{v.hipaa_section}] {v.violation_type.replace('_', ' ').title()}")
            log(f"    │    Agent: {v.agent_id[:30]}")
            log(f"    │    {v.description[:80]}")

    db_stats = store.get_database_stats()
    log(f"\n[+] Database summary:")
    log(f"    ├─ Total agents:     {db_stats['total_agents']}")
    log(f"    ├─ Total actions:    {db_stats['total_actions']}")
    log(f"    ├─ Total violations: {db_stats['total_violations']}")
    log(f"    └─ Open violations:  {db_stats['open_violations']}")

    log("\n[+] Demo complete. Run the dashboard:")
    log(f"    audit serve --db {db}\n")

    return store, violations


if __name__ == "__main__":
    run_demo()
