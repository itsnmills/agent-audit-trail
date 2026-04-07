#!/usr/bin/env python3
"""
Unit tests for agent_audit models, ingestion, storage, compliance, and violation detection.

Test coverage:
  - AgentIdentity: field validation, property methods, serialization
  - AgentAction: hash computation, tamper detection, PHI classification
  - ComplianceControl: weight calculation, scoring
  - ViolationRecord: breach heuristics, risk scoring
  - ActionIngester: normalization, validation, CEF/FHIR parsing
  - AuditStore: CRUD, hash chain integrity, append-only enforcement
  - ComplianceEngine: control assessment, scoring, gap analysis
  - ViolationDetector: rule-based detection (V-001 through V-020)
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the package is importable from the project root
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent_audit.models import (
    AgentAction,
    AgentIdentity,
    ComplianceControl,
    ComplianceReport,
    ViolationRecord,
)
from agent_audit.ingestion import ActionIngester, _normalize_phi_category, _validate_timestamp
from agent_audit.config import (
    BULK_ACCESS_THRESHOLD,
    CREDENTIAL_ROTATION_MAX_DAYS,
    GENESIS_HASH,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ts(days_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


@pytest.fixture
def sample_agent() -> AgentIdentity:
    return AgentIdentity(
        agent_id=str(uuid.uuid4()),
        agent_name="Test Clinical Documentation Agent v1.0",
        agent_type="clinical_documentation",
        vendor="Custom",
        model_type="llm",
        model_version="gpt-4o",
        deployment_env="production",
        owner_id="EMP-001",
        owner_role="CMIO",
        department="Primary Care",
        registered_at=_ts(days_ago=30),
        last_authenticated=_utc_now(),
        status="active",
        risk_tier="high",
        phi_scope="patient_record",
        permissions=["read_patient_summary", "write_clinical_note"],
        baa_reference="",
        authentication_method="oauth2_client_credentials",
        credential_rotation_days=90,
        last_credential_rotation=_ts(days_ago=30),
        tags={"intended_use": "Clinical documentation"},
    )


@pytest.fixture
def sample_action(sample_agent: AgentIdentity) -> AgentAction:
    return AgentAction(
        action_id=str(uuid.uuid4()),
        timestamp=_utc_now(),
        agent_id=sample_agent.agent_id,
        session_id=str(uuid.uuid4()),
        workflow_id=f"wf_{uuid.uuid4().hex[:8]}",
        human_authorizer_id="DR-1234",
        human_authorizer_role="Attending Physician",
        delegation_chain=["Dr. Smith", "Epic Workflow Engine", sample_agent.agent_name],
        operation="read",
        operation_detail="Read patient encounter note for discharge summary generation",
        resource_type="patient_record",
        resource_id="MRN-123456",
        phi_categories=["demographics", "diagnosis", "medications"],
        phi_volume=1,
        data_classification="phi",
        source_system="Epic EHR",
        target_system="DAX Module",
        network_zone="internal_clinical",
        access_justification="Generating discharge summary for encounter WF-001",
        minimum_necessary_scope="encounter_specific",
        policy_applied="CLINICAL_DOC_POLICY",
        encryption_in_transit=True,
        encryption_at_rest=True,
        encryption_algorithm="AES-256-GCM",
        fips_validated=True,
        input_hash=hashlib.sha256(b"test_input").hexdigest(),
        output_hash=hashlib.sha256(b"test_output").hexdigest(),
        data_modified=False,
        modification_type="none",
        status="completed",
        duration_ms=500,
        previous_hash=GENESIS_HASH,
        record_hash="",
        chain_sequence=1,
    )


@pytest.fixture
def temp_db() -> Path:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_audit.db"


# ---------------------------------------------------------------------------
# AgentIdentity Tests
# ---------------------------------------------------------------------------

class TestAgentIdentity:

    def test_agent_identity_creation(self, sample_agent: AgentIdentity) -> None:
        assert sample_agent.agent_id
        assert sample_agent.agent_name
        assert sample_agent.agent_type == "clinical_documentation"

    def test_credential_age_fresh(self, sample_agent: AgentIdentity) -> None:
        """Credentials rotated 30 days ago should be within limit."""
        assert sample_agent.credential_age_days < CREDENTIAL_ROTATION_MAX_DAYS

    def test_credential_age_stale(self, sample_agent: AgentIdentity) -> None:
        """Credentials rotated 120 days ago should exceed limit."""
        sample_agent.last_credential_rotation = _ts(days_ago=120)
        assert sample_agent.credential_age_days > CREDENTIAL_ROTATION_MAX_DAYS

    def test_credential_age_missing(self, sample_agent: AgentIdentity) -> None:
        """Missing last_credential_rotation returns 9999."""
        sample_agent.last_credential_rotation = ""
        assert sample_agent.credential_age_days == 9999

    def test_is_third_party_custom(self, sample_agent: AgentIdentity) -> None:
        """Custom/internal vendors are not third-party."""
        sample_agent.vendor = "Custom"
        assert sample_agent.is_third_party is False

    def test_is_third_party_external(self, sample_agent: AgentIdentity) -> None:
        """External vendor agents are third-party (require BAA)."""
        sample_agent.vendor = "Nuance/DAX"
        assert sample_agent.is_third_party is True

    def test_to_dict_contains_all_fields(self, sample_agent: AgentIdentity) -> None:
        d = sample_agent.to_dict()
        assert "agent_id" in d
        assert "phi_scope" in d
        assert "permissions" in d
        assert isinstance(d["permissions"], list)

    def test_serialization_roundtrip(self, sample_agent: AgentIdentity) -> None:
        """Serialization to dict should be lossless."""
        d = sample_agent.to_dict()
        assert d["agent_id"] == sample_agent.agent_id
        assert d["agent_name"] == sample_agent.agent_name
        assert d["permissions"] == sample_agent.permissions


# ---------------------------------------------------------------------------
# AgentAction Tests
# ---------------------------------------------------------------------------

class TestAgentAction:

    def test_action_creation(self, sample_action: AgentAction) -> None:
        assert sample_action.action_id
        assert sample_action.timestamp
        assert sample_action.operation == "read"

    def test_compute_hash_deterministic(self, sample_action: AgentAction) -> None:
        """Same action always produces same hash."""
        h1 = sample_action.compute_hash()
        h2 = sample_action.compute_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_compute_hash_changes_on_modification(self, sample_action: AgentAction) -> None:
        """Modifying any field changes the hash — tamper detection."""
        h1 = sample_action.compute_hash()
        sample_action.operation = "delete"  # Tamper!
        h2 = sample_action.compute_hash()
        assert h1 != h2

    def test_hash_excludes_record_hash_field(self, sample_action: AgentAction) -> None:
        """record_hash field must be excluded from hash computation (circular dependency)."""
        sample_action.record_hash = ""
        h1 = sample_action.compute_hash()
        sample_action.record_hash = "some_hash_value"
        h2 = sample_action.compute_hash()
        assert h1 == h2  # record_hash is excluded

    def test_involves_phi_true(self, sample_action: AgentAction) -> None:
        """PHI-classified actions must be flagged."""
        sample_action.data_classification = "phi"
        assert sample_action.involves_phi is True

    def test_involves_phi_false(self, sample_action: AgentAction) -> None:
        """De-identified data should not be flagged as PHI."""
        sample_action.data_classification = "de_identified"
        assert sample_action.involves_phi is False

    def test_is_external_transmission(self, sample_action: AgentAction) -> None:
        """External network zone should flag as external transmission."""
        sample_action.network_zone = "external"
        assert sample_action.is_external_transmission is True
        sample_action.network_zone = "internal_clinical"
        assert sample_action.is_external_transmission is False

    def test_to_dict_serializable(self, sample_action: AgentAction) -> None:
        d = sample_action.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d, default=str)
        assert json_str


# ---------------------------------------------------------------------------
# ComplianceControl Tests
# ---------------------------------------------------------------------------

class TestComplianceControl:

    def test_required_control_weight(self) -> None:
        """Required controls are weighted 2x."""
        ctrl = ComplianceControl(
            control_id="AC-001",
            hipaa_section="§164.312(a)(2)(i)",
            hipaa_standard="Unique User Identification",
            requirement_type="required",
            description="Test",
        )
        assert ctrl.weight == 2.0

    def test_addressable_control_weight(self) -> None:
        """Addressable controls are weighted 1x."""
        ctrl = ComplianceControl(
            control_id="AC-004",
            hipaa_section="§164.312(a)(2)(iii)",
            hipaa_standard="Automatic Logoff",
            requirement_type="addressable",
            description="Test",
        )
        assert ctrl.weight == 1.0

    def test_is_critical_finding(self) -> None:
        ctrl = ComplianceControl(
            control_id="TS-001",
            hipaa_section="§164.312(e)",
            hipaa_standard="Encryption",
            requirement_type="required",
            description="Test",
            status="non_compliant",
            severity="critical",
        )
        assert ctrl.is_critical_finding is True

    def test_not_critical_if_compliant(self) -> None:
        ctrl = ComplianceControl(
            control_id="TS-001",
            hipaa_section="§164.312(e)",
            hipaa_standard="Encryption",
            requirement_type="required",
            description="Test",
            status="compliant",
            severity="critical",
        )
        assert ctrl.is_critical_finding is False


# ---------------------------------------------------------------------------
# ViolationRecord Tests
# ---------------------------------------------------------------------------

class TestViolationRecord:

    def test_reportable_breach_detection(self) -> None:
        """High-severity confirmed PHI exposure with patients should be reportable."""
        v = ViolationRecord(
            violation_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id="agent-001",
            action_id="action-001",
            violation_type="unencrypted_phi",
            hipaa_section="§164.312(e)",
            severity="critical",
            severity_score=9.5,
            phi_impact="confirmed_phi_exposure",
            patient_count=150,
        )
        assert v.is_reportable_breach is True

    def test_not_reportable_no_patients(self) -> None:
        v = ViolationRecord(
            violation_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id="agent-001",
            action_id="action-001",
            violation_type="unencrypted_phi",
            hipaa_section="§164.312(e)",
            severity="critical",
            severity_score=9.5,
            phi_impact="confirmed_phi_exposure",
            patient_count=0,
        )
        assert v.is_reportable_breach is False

    def test_not_reportable_potential_only(self) -> None:
        v = ViolationRecord(
            violation_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id="agent-001",
            action_id="action-001",
            violation_type="missing_authentication",
            hipaa_section="§164.312(d)",
            severity="critical",
            severity_score=9.5,
            phi_impact="potential_phi_exposure",
            patient_count=50,
        )
        assert v.is_reportable_breach is False


# ---------------------------------------------------------------------------
# ActionIngester Tests
# ---------------------------------------------------------------------------

class TestActionIngester:

    def test_ingest_minimal_action(self, sample_agent: AgentIdentity) -> None:
        """Ingester must handle a minimal valid action dict."""
        ingester = ActionIngester()
        raw = {
            "agent_id": sample_agent.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": "wf-001",
            "human_authorizer_id": "DR-001",
            "human_authorizer_role": "Physician",
            "operation": "read",
            "delegation_chain": ["Dr. Test", "Epic", "Agent"],
        }
        action = ingester.ingest_action(raw)
        assert action.action_id  # Should be auto-generated
        assert action.timestamp  # Should be auto-generated
        assert action.record_hash  # Should be computed

    def test_ingest_sets_record_hash(self, sample_agent: AgentIdentity) -> None:
        """Record hash must be computed during ingestion."""
        ingester = ActionIngester()
        raw = {
            "agent_id": sample_agent.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": "wf-001",
            "human_authorizer_id": "DR-001",
            "human_authorizer_role": "Physician",
            "operation": "read",
            "delegation_chain": ["Dr. Test", "Agent"],
        }
        action = ingester.ingest_action(raw)
        assert len(action.record_hash) == 64  # SHA-256 hex

    def test_validate_missing_human_authorizer(self, sample_agent: AgentIdentity) -> None:
        """Missing human_authorizer_id must produce a validation error."""
        ingester = ActionIngester()
        raw = {
            "action_id": str(uuid.uuid4()),
            "timestamp": _utc_now(),
            "agent_id": sample_agent.agent_id,
            "session_id": str(uuid.uuid4()),
            "workflow_id": "wf-001",
            "human_authorizer_id": "",  # Missing!
            "human_authorizer_role": "Physician",
            "operation": "read",
            "delegation_chain": ["Dr. Test", "Agent"],
        }
        action = ingester.ingest_action(raw)
        errors = ingester.validate_action(action)
        assert any("human_authorizer_id" in e for e in errors)

    def test_validate_short_delegation_chain(self, sample_agent: AgentIdentity) -> None:
        """Delegation chain with <2 entries must fail validation."""
        ingester = ActionIngester()
        action = AgentAction(
            action_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id=sample_agent.agent_id,
            session_id=str(uuid.uuid4()),
            workflow_id="wf-001",
            human_authorizer_id="DR-001",
            human_authorizer_role="Physician",
            delegation_chain=["Only One Entry"],  # Too short!
            operation="read",
        )
        errors = ingester.validate_action(action)
        assert any("delegation_chain" in e for e in errors)

    def test_validate_encryption_required_for_phi(self, sample_agent: AgentIdentity) -> None:
        """Missing encryption when accessing PHI must produce validation error."""
        ingester = ActionIngester()
        action = AgentAction(
            action_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id=sample_agent.agent_id,
            session_id=str(uuid.uuid4()),
            workflow_id="wf-001",
            human_authorizer_id="DR-001",
            human_authorizer_role="Physician",
            delegation_chain=["Dr. Test", "Agent"],
            operation="read",
            data_classification="phi",
            phi_categories=["demographics"],
            encryption_in_transit=False,  # Missing encryption!
        )
        errors = ingester.validate_action(action)
        assert any("encryption_in_transit" in e or "encryption" in e.lower() for e in errors)

    def test_normalize_phi_categories(self) -> None:
        """PHI category synonyms must be mapped to canonical taxonomy."""
        ingester = ActionIngester()
        raw = ["patient_name", "birth_date", "telephone", "labs", "icd10"]
        normalized = ingester.normalize_phi_categories(raw)
        assert "demographics" in normalized
        assert "dob" in normalized
        assert "phone" in normalized
        assert "lab_values" in normalized
        assert "diagnosis" in normalized

    def test_normalize_phi_categories_deduplication(self) -> None:
        """Duplicate categories must be deduplicated."""
        ingester = ActionIngester()
        raw = ["demographics", "name", "patient_name"]  # All map to demographics
        normalized = ingester.normalize_phi_categories(raw)
        assert normalized.count("demographics") == 1

    def test_timestamp_normalization_no_tz(self) -> None:
        """Timestamp without timezone should be accepted with UTC assumption."""
        ingester = ActionIngester()
        raw = {
            "agent_id": "agent-001",
            "session_id": str(uuid.uuid4()),
            "workflow_id": "wf-001",
            "human_authorizer_id": "DR-001",
            "human_authorizer_role": "Physician",
            "operation": "read",
            "timestamp": "2026-04-07 12:00:00",  # No timezone
            "delegation_chain": ["Dr. Test", "Agent"],
        }
        action = ingester.ingest_action(raw)
        # Should not raise; timestamp normalized to include UTC
        assert "2026-04-07" in action.timestamp

    def test_operation_normalization(self) -> None:
        """Operation synonyms must be normalized to canonical vocabulary."""
        ingester = ActionIngester()
        raw = {
            "agent_id": "agent-001",
            "session_id": str(uuid.uuid4()),
            "workflow_id": "wf-001",
            "human_authorizer_id": "DR-001",
            "human_authorizer_role": "Physician",
            "operation": "get",  # Synonym for "read"
            "delegation_chain": ["Dr. Test", "Agent"],
        }
        action = ingester.ingest_action(raw)
        assert action.operation == "read"

    def test_shadow_agent_detection(self) -> None:
        """Action from unregistered agent must produce validation warning."""
        ingester = ActionIngester(known_agent_ids={"registered-agent-001"})
        action = AgentAction(
            action_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id="UNREGISTERED-shadow-agent",  # Not in known_agent_ids!
            session_id=str(uuid.uuid4()),
            workflow_id="wf-001",
            human_authorizer_id="DR-001",
            human_authorizer_role="Physician",
            delegation_chain=["Dr. Test", "Shadow Agent"],
            operation="read",
        )
        errors = ingester.validate_action(action)
        assert any("shadow" in e.lower() or "unregistered" in e.lower() or "V-015" in e for e in errors)

    def test_fhir_audit_event_ingestion(self) -> None:
        """FHIR R4 AuditEvent must be correctly parsed into AgentAction."""
        ingester = ActionIngester()
        fhir_event = {
            "resourceType": "AuditEvent",
            "id": str(uuid.uuid4()),
            "recorded": _utc_now(),
            "action": "R",
            "outcome": "0",
            "agent": [
                {
                    "requestor": True,
                    "who": {"display": "Dr. Jane Smith", "identifier": {"value": "NPI-1234567890"}},
                    "role": [{"coding": [{"display": "Attending Physician"}]}],
                },
                {
                    "requestor": False,
                    "who": {"display": "DAX Clinical AI", "identifier": {"value": "agent-dax-001"}},
                },
            ],
            "entity": [
                {
                    "what": {
                        "reference": "Patient/MRN-123456",
                        "type": {"display": "Patient", "code": "Patient"},
                    },
                    "type": {"code": "Patient"},
                },
            ],
            "source": {"observer": {"display": "Epic EHR"}},
        }
        action = ingester.ingest_fhir_audit_event(fhir_event)
        assert action.operation == "read"  # FHIR "R" → "read"
        assert action.human_authorizer_id == "NPI-1234567890"
        assert action.agent_id == "agent-dax-001"
        assert action.status == "completed"

    def test_cef_ingestion(self) -> None:
        """CEF-formatted syslog line must be parsed into AgentAction."""
        ingester = ActionIngester()
        cef_line = (
            "CEF:0|HealthSystem|EHR|1.0|ACCESS_001|Patient Record Read|5|"
            "deviceExternalId=ACTION-001 rt=2026-04-07T12:00:00Z "
            "duid=agent-001 suid=DR-001 sntdom=Attending Physician "
            "fname=MRN-123456 cs2=SESSION-001 cs3=WF-001 "
            "dhost=Epic-EHR dst=DAX-Module cn1=450"
        )
        action = ingester.ingest_cef(cef_line)
        assert action.agent_id == "agent-001"
        assert action.human_authorizer_id == "DR-001"
        assert action.operation == "read"
        assert action.duration_ms == 450

    def test_cef_invalid_raises(self) -> None:
        """Non-CEF input must raise ValueError."""
        ingester = ActionIngester()
        with pytest.raises(ValueError, match="CEF"):
            ingester.ingest_cef("This is not a CEF line")


# ---------------------------------------------------------------------------
# Timestamp validation
# ---------------------------------------------------------------------------

class TestTimestampValidation:

    def test_valid_iso_with_tz(self) -> None:
        assert _validate_timestamp("2026-04-07T12:00:00+00:00") == ""
        assert _validate_timestamp("2026-04-07T12:00:00Z") == ""
        assert _validate_timestamp(_utc_now()) == ""

    def test_invalid_no_tz(self) -> None:
        error = _validate_timestamp("2026-04-07T12:00:00")
        assert error  # Non-empty error message

    def test_invalid_format(self) -> None:
        error = _validate_timestamp("not-a-date")
        assert error


# ---------------------------------------------------------------------------
# AuditStore Tests
# ---------------------------------------------------------------------------

class TestAuditStore:

    def test_store_initialization(self, temp_db: Path) -> None:
        """Store must initialize database and genesis record."""
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        assert temp_db.exists()
        stats = store.get_database_stats()
        assert stats["chain_genesis_hash"] == GENESIS_HASH

    def test_store_and_retrieve_agent(self, temp_db: Path, sample_agent: AgentIdentity) -> None:
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        store.store_agent(sample_agent)
        retrieved = store.get_agent(sample_agent.agent_id)
        assert retrieved is not None
        assert retrieved.agent_id == sample_agent.agent_id
        assert retrieved.agent_name == sample_agent.agent_name

    def test_store_and_retrieve_action(self, temp_db: Path, sample_action: AgentAction) -> None:
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        stored_id = store.store_action(sample_action)
        assert stored_id == sample_action.action_id
        retrieved = store.get_action(sample_action.action_id)
        assert retrieved is not None
        assert retrieved.operation == sample_action.operation
        assert retrieved.agent_id == sample_action.agent_id

    def test_hash_chain_integrity_single_record(self, temp_db: Path, sample_action: AgentAction) -> None:
        """Chain with single record must be valid."""
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        store.store_action(sample_action)
        valid, errors = store.verify_chain_integrity()
        assert valid
        assert errors == []

    def test_hash_chain_integrity_multiple_records(self, temp_db: Path, sample_agent: AgentIdentity) -> None:
        """Chain with multiple sequential records must be valid."""
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        ingester = ActionIngester()

        for i in range(5):
            action = ingester.ingest_action({
                "agent_id": sample_agent.agent_id,
                "session_id": str(uuid.uuid4()),
                "workflow_id": f"wf-{i}",
                "human_authorizer_id": "DR-001",
                "human_authorizer_role": "Physician",
                "operation": "read",
                "delegation_chain": ["Dr. Test", "Agent"],
            })
            store.store_action(action)

        valid, errors = store.verify_chain_integrity()
        assert valid, f"Chain should be valid but got errors: {errors}"

    def test_hash_chain_broken_by_modification(self, temp_db: Path, sample_action: AgentAction) -> None:
        """Modifying a stored record must break chain integrity."""
        from agent_audit.storage import AuditStore
        from sqlalchemy import text

        store = AuditStore(db_path=temp_db)
        store.store_action(sample_action)

        # Directly modify the database (simulating tampering)
        with store.engine.connect() as conn:
            conn.execute(
                text("UPDATE agent_actions SET operation = 'delete' WHERE action_id = :aid"),
                {"aid": sample_action.action_id},
            )
            conn.commit()

        # Chain integrity must fail
        valid, errors = store.verify_chain_integrity()
        assert not valid
        assert len(errors) > 0

    def test_store_violation(self, temp_db: Path) -> None:
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        v = ViolationRecord(
            violation_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id="agent-001",
            action_id="action-001",
            violation_type="unencrypted_phi",
            hipaa_section="§164.312(e)",
            severity="critical",
            severity_score=9.5,
        )
        stored_id = store.store_violation(v)
        assert stored_id == v.violation_id

    def test_query_actions_by_agent(self, temp_db: Path, sample_agent: AgentIdentity) -> None:
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        ingester = ActionIngester()

        for i in range(3):
            action = ingester.ingest_action({
                "agent_id": sample_agent.agent_id,
                "session_id": str(uuid.uuid4()),
                "workflow_id": f"wf-{i}",
                "human_authorizer_id": "DR-001",
                "human_authorizer_role": "Physician",
                "operation": "read",
                "delegation_chain": ["Dr. Test", "Agent"],
            })
            store.store_action(action)

        results = store.query_actions(agent_id=sample_agent.agent_id)
        assert len(results) == 3
        assert all(a.agent_id == sample_agent.agent_id for a in results)

    def test_agent_stats(self, temp_db: Path, sample_agent: AgentIdentity) -> None:
        from agent_audit.storage import AuditStore
        store = AuditStore(db_path=temp_db)
        store.store_agent(sample_agent)
        ingester = ActionIngester()

        for _ in range(4):
            action = ingester.ingest_action({
                "agent_id": sample_agent.agent_id,
                "session_id": str(uuid.uuid4()),
                "workflow_id": "wf-001",
                "human_authorizer_id": "DR-001",
                "human_authorizer_role": "Physician",
                "operation": "read",
                "delegation_chain": ["Dr. Test", "Agent"],
                "phi_categories": ["demographics"],
                "data_classification": "phi",
                "phi_volume": 1,
            })
            store.store_action(action)

        stats = store.get_agent_stats(sample_agent.agent_id)
        assert stats["total_actions"] == 4
        assert stats["agent_id"] == sample_agent.agent_id


# ---------------------------------------------------------------------------
# ComplianceEngine Tests
# ---------------------------------------------------------------------------

class TestComplianceEngine:

    def test_compliance_score_all_compliant(self) -> None:
        """100% compliant controls must yield score ~100."""
        from agent_audit.compliance import ComplianceEngine
        from agent_audit.models import ComplianceControl

        mock_store = MagicMock()
        engine = ComplianceEngine(store=mock_store)

        controls = [
            ComplianceControl(
                control_id=f"AC-{i:03d}",
                hipaa_section="§164.312(a)",
                hipaa_standard="Test",
                requirement_type="required",
                description="Test",
                status="compliant",
            )
            for i in range(5)
        ]
        score = engine.compute_compliance_score(controls)
        assert score == 100.0

    def test_compliance_score_all_non_compliant(self) -> None:
        """100% non-compliant controls must yield score 0."""
        from agent_audit.compliance import ComplianceEngine

        mock_store = MagicMock()
        engine = ComplianceEngine(store=mock_store)

        controls = [
            ComplianceControl(
                control_id=f"AC-{i:03d}",
                hipaa_section="§164.312(a)",
                hipaa_standard="Test",
                requirement_type="required",
                description="Test",
                status="non_compliant",
            )
            for i in range(5)
        ]
        score = engine.compute_compliance_score(controls)
        assert score == 0.0

    def test_compliance_score_partial(self) -> None:
        """Partially compliant controls must yield intermediate score."""
        from agent_audit.compliance import ComplianceEngine

        mock_store = MagicMock()
        engine = ComplianceEngine(store=mock_store)

        controls = [
            ComplianceControl(
                control_id="AC-001",
                hipaa_section="§164.312(a)",
                hipaa_standard="Test",
                requirement_type="required",
                description="Test",
                status="partially_compliant",
            ),
        ]
        score = engine.compute_compliance_score(controls)
        assert 0 < score < 100

    def test_required_controls_weighted_higher(self) -> None:
        """Required controls must have higher impact on score than addressable."""
        from agent_audit.compliance import ComplianceEngine

        mock_store = MagicMock()
        engine = ComplianceEngine(store=mock_store)

        # One required non-compliant, one addressable compliant
        controls_a = [
            ComplianceControl("C1", "§164.312", "Test", "required", "Test", status="non_compliant"),
            ComplianceControl("C2", "§164.312", "Test", "addressable", "Test", status="compliant"),
        ]
        # One required compliant, one addressable non-compliant
        controls_b = [
            ComplianceControl("C1", "§164.312", "Test", "required", "Test", status="compliant"),
            ComplianceControl("C2", "§164.312", "Test", "addressable", "Test", status="non_compliant"),
        ]
        score_a = engine.compute_compliance_score(controls_a)
        score_b = engine.compute_compliance_score(controls_b)
        # Required compliant scenario should score higher
        assert score_b > score_a

    def test_rating_boundaries(self) -> None:
        """Rating thresholds must map correctly."""
        from agent_audit.compliance import ComplianceEngine
        mock_store = MagicMock()
        engine = ComplianceEngine(store=mock_store)

        assert "Compliant" in engine.get_rating(95.0)
        assert "Substantially" in engine.get_rating(80.0)
        assert "Partially" in engine.get_rating(60.0)
        assert "Non-Compliant" in engine.get_rating(40.0)
        assert "Critical" in engine.get_rating(15.0)

    def test_nist_ai_rmf_mapping(self) -> None:
        """NIST AI RMF scores must be returned per function."""
        from agent_audit.compliance import ComplianceEngine, HIPAA_CONTROLS

        mock_store = MagicMock()
        engine = ComplianceEngine(store=mock_store)

        # Set some controls to compliant/non-compliant
        import copy
        results = [copy.deepcopy(c) for c in HIPAA_CONTROLS[:5]]
        for c in results:
            c.status = "compliant"

        rmf = engine.map_to_nist_ai_rmf(results)
        # Should have at least some functions
        assert isinstance(rmf, dict)
        for score in rmf.values():
            assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# ViolationDetector Tests
# ---------------------------------------------------------------------------

class TestViolationDetector:

    def test_v001_unencrypted_phi(self, temp_db: Path, sample_action: AgentAction) -> None:
        """V-001: Unencrypted PHI access must be detected."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        detector = ViolationDetector(store=store)

        sample_action.encryption_in_transit = False
        sample_action.data_classification = "phi"
        sample_action.phi_categories = ["demographics"]

        violations = detector.analyze_action(sample_action)
        v001 = [v for v in violations if "unencrypted" in v.violation_type.lower() or "V-001" in v.description]
        assert len(v001) > 0
        assert any(v.severity == "critical" for v in v001)

    def test_v002_missing_human_authorizer(self, temp_db: Path, sample_action: AgentAction) -> None:
        """V-002: Missing human authorizer must be detected."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        detector = ViolationDetector(store=store)

        sample_action.human_authorizer_id = ""
        violations = detector.analyze_action(sample_action)
        v002 = [v for v in violations if "missing_human" in v.violation_type or "authorizer" in v.description.lower()]
        assert len(v002) > 0
        assert any(v.severity == "critical" for v in v002)

    def test_v003_external_unencrypted(self, temp_db: Path, sample_action: AgentAction) -> None:
        """V-003: Unencrypted PHI transmitted externally must be detected."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        detector = ViolationDetector(store=store)

        sample_action.network_zone = "external"
        sample_action.encryption_in_transit = False
        sample_action.data_classification = "phi"
        sample_action.phi_categories = ["demographics"]

        violations = detector.analyze_action(sample_action)
        v003 = [v for v in violations if "external" in v.violation_type.lower() or "external" in v.description.lower()]
        assert len(v003) > 0

    def test_v014_incomplete_delegation_chain(self, temp_db: Path, sample_action: AgentAction) -> None:
        """V-014: Short delegation chain must be detected."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        detector = ViolationDetector(store=store)

        sample_action.delegation_chain = ["Only One"]  # < 2 required
        violations = detector.analyze_action(sample_action)
        v014 = [v for v in violations if "delegation" in v.violation_type.lower() or "delegation" in v.description.lower()]
        assert len(v014) > 0

    def test_v018_missing_operation_detail(self, temp_db: Path, sample_action: AgentAction) -> None:
        """V-018: Missing operation_detail on PHI actions must be flagged."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        detector = ViolationDetector(store=store)

        sample_action.operation_detail = ""  # Missing!
        sample_action.data_classification = "phi"
        sample_action.phi_categories = ["demographics"]

        violations = detector.analyze_action(sample_action)
        v018 = [v for v in violations if "missing_operation" in v.violation_type or "operation_detail" in v.description.lower()]
        assert len(v018) > 0
        assert any(v.severity == "low" for v in v018)

    def test_v005_bulk_exfiltration_batch(self, temp_db: Path, sample_agent: AgentIdentity) -> None:
        """V-005: Bulk PHI access in a session must be detected in batch analysis."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        store.store_agent(sample_agent)
        ingester = ActionIngester()
        detector = ViolationDetector(store=store)

        session_id = str(uuid.uuid4())
        actions = []
        for i in range(BULK_ACCESS_THRESHOLD + 20):  # Exceeds threshold
            action = ingester.ingest_action({
                "agent_id": sample_agent.agent_id,
                "session_id": session_id,
                "workflow_id": "bulk-wf",
                "human_authorizer_id": "DR-001",
                "human_authorizer_role": "Physician",
                "operation": "read",
                "delegation_chain": ["Dr. Test", "Agent"],
                "data_classification": "phi",
                "phi_categories": ["demographics"],
                "phi_volume": 1,
            })
            actions.append(action)

        violations = detector.analyze_batch(actions)
        v005 = [v for v in violations if "bulk" in v.violation_type.lower() or "exfil" in v.violation_type.lower()]
        assert len(v005) > 0
        assert any(v.severity == "critical" for v in v005)

    def test_detect_shadow_agents(self, temp_db: Path, sample_agent: AgentIdentity, sample_action: AgentAction) -> None:
        """Shadow agents appearing in action log but not registry must be detected."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        # Register sample_agent but don't register the agent in sample_action
        # Actually, use a different agent_id for the shadow
        shadow_action = AgentAction(
            action_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            agent_id="unregistered-shadow-xyz",  # Not registered!
            session_id=str(uuid.uuid4()),
            workflow_id="wf-shadow",
            human_authorizer_id="DR-001",
            human_authorizer_role="Physician",
            delegation_chain=["Shadow Agent"],
            operation="read",
            data_classification="phi",
            phi_categories=["demographics"],
            phi_volume=5,
        )
        shadow_action.record_hash = shadow_action.compute_hash()
        store.store_action(shadow_action)

        detector = ViolationDetector(store=store)
        shadow_violations = detector.detect_shadow_agents()
        assert len(shadow_violations) > 0
        assert any("shadow" in v.description.lower() or "unregistered" in v.description.lower()
                   for v in shadow_violations)

    def test_no_false_positive_compliant_action(self, temp_db: Path, sample_action: AgentAction) -> None:
        """A fully compliant action should not trigger V-001, V-002, V-003, or V-014."""
        from agent_audit.storage import AuditStore
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        detector = ViolationDetector(store=store, known_agent_ids={sample_action.agent_id})

        critical_violations = [
            v for v in detector.analyze_action(sample_action)
            if v.severity == "critical"
        ]
        # A properly configured action should not generate critical violations
        # (V-016 may fire if after-hours, but that's low severity)
        non_low = [v for v in critical_violations if v.severity != "low"]
        assert len(non_low) == 0, f"Unexpected critical violations: {[v.violation_type for v in non_low]}"


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestIntegration:

    def test_end_to_end_workflow(self, temp_db: Path) -> None:
        """Full workflow: ingest → store → assess → report."""
        from agent_audit.storage import AuditStore
        from agent_audit.ingestion import ActionIngester
        from agent_audit.compliance import ComplianceEngine
        from agent_audit.violations import ViolationDetector

        store = AuditStore(db_path=temp_db)
        ingester = ActionIngester()
        engine = ComplianceEngine(store=store)
        detector = ViolationDetector(store=store)

        # Register an agent
        agent = AgentIdentity(
            agent_id=str(uuid.uuid4()),
            agent_name="Integration Test Agent",
            agent_type="clinical_documentation",
            vendor="Custom",
            model_type="llm",
            model_version="test-v1",
            deployment_env="test",
            owner_id="EMP-001",
            owner_role="IT Director",
            department="Test",
            registered_at=_utc_now(),
            last_authenticated=_utc_now(),
            status="active",
            risk_tier="medium",
            phi_scope="patient_record",
            permissions=["read_patient_summary"],
            authentication_method="oauth2_client_credentials",
            credential_rotation_days=90,
            last_credential_rotation=_ts(days_ago=30),
            tags={},
        )
        store.store_agent(agent)

        # Ingest 10 actions
        for i in range(10):
            action = ingester.ingest_action({
                "agent_id": agent.agent_id,
                "session_id": str(uuid.uuid4()),
                "workflow_id": f"wf-{i}",
                "human_authorizer_id": "DR-001",
                "human_authorizer_role": "Physician",
                "operation": "read",
                "operation_detail": f"Read patient record #{i}",
                "delegation_chain": ["Dr. Smith", "EHR Workflow", agent.agent_name],
                "data_classification": "phi",
                "phi_categories": ["demographics", "diagnosis"],
                "phi_volume": 1,
                "encryption_in_transit": True,
                "encryption_at_rest": True,
                "encryption_algorithm": "AES-256-GCM",
                "fips_validated": True,
                "access_justification": f"Clinical workflow #{i}",
                "minimum_necessary_scope": "encounter_specific",
            })
            store.store_action(action)

        # Verify chain
        valid, errors = store.verify_chain_integrity()
        assert valid, f"Chain integrity failed: {errors}"

        # Run assessment
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=1)).isoformat()
        end = now.isoformat()
        results = engine.assess_all_controls(start, end)
        assert len(results) == len(engine.controls)

        # Score
        score = engine.compute_compliance_score(results)
        assert 0 <= score <= 100

        # Database stats
        stats = store.get_database_stats()
        assert stats["total_actions"] == 10
        assert stats["total_agents"] == 1
