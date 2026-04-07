#!/usr/bin/env python3
"""
SQLite storage engine with tamper-evident logging.

Design principles:
  - APPEND-ONLY audit log: no UPDATE or DELETE on AgentActionORM records
  - SHA-256 hash chain: each record links to its predecessor
  - Full chain integrity verification
  - Efficient querying by agent, time range, operation, severity
  - Automatic genesis record initialization

HIPAA grounding:
  §164.312(b)  — Audit Controls: logs must be tamper-evident
  §164.316(b)  — Documentation: records retained for 6 years
  NIST SP 800-92 — Guide to Computer Security Log Management:
    recommends cryptographic integrity for audit logs
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import and_, func, or_, text
from sqlalchemy.orm import Session, sessionmaker

from .config import (
    DB_PATH,
    GENESIS_HASH,
)
from .models import (
    AgentAction,
    AgentActionORM,
    AgentIdentity,
    AgentIdentityORM,
    AuditChainMetaORM,
    Base,
    ComplianceReport,
    ComplianceReportORM,
    ViolationRecord,
    ViolationRecordORM,
    get_engine,
    init_db,
)

logger = logging.getLogger(__name__)


class AuditStore:
    """
    Persistent storage for the AI Agent Audit Trail.

    Implements an append-only SQLite database with a tamper-evident SHA-256
    hash chain across all action records. Any modification, insertion at an
    arbitrary position, or deletion of an action record breaks the chain
    and is detected by verify_chain_integrity().

    §164.312(b): This class is the technical implementation of the "hardware,
    software, and/or procedural mechanisms that record and examine activity"
    requirement. The append-only design and hash chain fulfill the tamper-evidence
    requirement flagged in NIST SP 800-66r2.

    Usage::

        store = AuditStore(db_path=Path("data/audit.db"))
        store.store_agent(agent_identity)
        store.store_action(agent_action)
        valid, errors = store.verify_chain_integrity()
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        """
        Initialize the audit store.

        Creates the database file and all tables if they do not exist.
        Initializes the genesis record if this is a fresh database.

        Args:
            db_path: Path to the SQLite database file.
                     Defaults to config.DB_PATH.
        """
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.engine = get_engine(str(self.db_path))
        init_db(self.engine)
        self.SessionFactory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self._ensure_genesis()
        logger.info("AuditStore initialized at %s", self.db_path)

    # ------------------------------------------------------------------
    # Context manager for sessions
    # ------------------------------------------------------------------

    @contextmanager
    def _session(self):
        """Provide a transactional session scope."""
        session = self.SessionFactory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Genesis initialization
    # ------------------------------------------------------------------

    def _ensure_genesis(self) -> None:
        """
        Initialize the audit chain metadata if this is a fresh database.

        The genesis record establishes the hash chain anchor point.
        All subsequent action records link back through this chain.
        """
        with self._session() as session:
            existing = session.query(AuditChainMetaORM).filter_by(key="genesis_hash").first()
            if not existing:
                session.add(AuditChainMetaORM(key="genesis_hash", value=GENESIS_HASH))
                session.add(AuditChainMetaORM(key="last_hash", value=GENESIS_HASH))
                session.add(AuditChainMetaORM(key="total_records", value="0"))
                session.add(AuditChainMetaORM(key="chain_initialized_at", value=_utc_now()))
                logger.info("Audit chain genesis initialized (hash=%s...)", GENESIS_HASH[:16])

    # ------------------------------------------------------------------
    # Agent Identity
    # ------------------------------------------------------------------

    def store_agent(self, agent: AgentIdentity) -> str:
        """
        Register or update an AI agent in the identity registry.

        §164.312(a)(2)(i): All agents must be registered with unique identifiers
        before they can perform any ePHI operations.

        Args:
            agent: The AgentIdentity to register.

        Returns:
            agent_id of the stored record.
        """
        with self._session() as session:
            existing = session.query(AgentIdentityORM).filter_by(agent_id=agent.agent_id).first()
            if existing:
                # Update mutable fields
                existing.agent_name = agent.agent_name
                existing.agent_type = agent.agent_type
                existing.vendor = agent.vendor
                existing.model_type = agent.model_type
                existing.model_version = agent.model_version
                existing.deployment_env = agent.deployment_env
                existing.owner_id = agent.owner_id
                existing.owner_role = agent.owner_role
                existing.department = agent.department
                existing.last_authenticated = agent.last_authenticated
                existing.status = agent.status
                existing.risk_tier = agent.risk_tier
                existing.phi_scope = agent.phi_scope
                existing.permissions = agent.permissions
                existing.baa_reference = agent.baa_reference
                existing.authentication_method = agent.authentication_method
                existing.credential_rotation_days = agent.credential_rotation_days
                existing.last_credential_rotation = agent.last_credential_rotation
                existing.tags = agent.tags
                logger.debug("Updated agent %s", agent.agent_id)
            else:
                orm = AgentIdentityORM(
                    agent_id=agent.agent_id,
                    agent_name=agent.agent_name,
                    agent_type=agent.agent_type,
                    vendor=agent.vendor,
                    model_type=agent.model_type,
                    model_version=agent.model_version,
                    deployment_env=agent.deployment_env,
                    owner_id=agent.owner_id,
                    owner_role=agent.owner_role,
                    department=agent.department,
                    registered_at=agent.registered_at,
                    last_authenticated=agent.last_authenticated,
                    status=agent.status,
                    risk_tier=agent.risk_tier,
                    phi_scope=agent.phi_scope,
                    permissions=agent.permissions,
                    baa_reference=agent.baa_reference,
                    authentication_method=agent.authentication_method,
                    credential_rotation_days=agent.credential_rotation_days,
                    last_credential_rotation=agent.last_credential_rotation,
                    tags=agent.tags,
                )
                session.add(orm)
                logger.info("Registered new agent %s (%s)", agent.agent_id, agent.agent_name)
        return agent.agent_id

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        """Retrieve an AgentIdentity by ID."""
        with self._session() as session:
            orm = session.query(AgentIdentityORM).filter_by(agent_id=agent_id).first()
            return orm.to_dataclass() if orm else None

    def list_agents(
        self,
        status: Optional[str] = None,
        risk_tier: Optional[str] = None,
        department: Optional[str] = None,
    ) -> list[AgentIdentity]:
        """
        List registered agents with optional filters.

        §164.308(a)(1): Covered entities must maintain a current inventory
        of all AI systems accessing PHI.
        """
        with self._session() as session:
            q = session.query(AgentIdentityORM)
            if status:
                q = q.filter(AgentIdentityORM.status == status)
            if risk_tier:
                q = q.filter(AgentIdentityORM.risk_tier == risk_tier)
            if department:
                q = q.filter(AgentIdentityORM.department == department)
            return [row.to_dataclass() for row in q.all()]

    # ------------------------------------------------------------------
    # Action Storage (APPEND-ONLY with hash chain)
    # ------------------------------------------------------------------

    def store_action(self, action: AgentAction) -> str:
        """
        Store an agent action in the tamper-evident audit log.

        APPEND-ONLY: this method only inserts new records, never updates
        or deletes existing ones. Any attempt to modify stored records would
        break the hash chain and be detected by verify_chain_integrity().

        Hash chain mechanics:
          1. Retrieve the last_hash from audit_chain_meta
          2. Set action.previous_hash = last_hash
          3. Compute action.record_hash = SHA-256(all fields except record_hash)
          4. Store the action
          5. Update last_hash = record_hash

        This ensures a continuous, unbroken chain where each record
        cryptographically commits to all preceding records.

        §164.312(b): Tamper-evident audit controls requirement.

        Args:
            action: The AgentAction to store.

        Returns:
            action_id of the stored record.
        """
        with self._session() as session:
            # Get current chain state
            last_hash_row = session.query(AuditChainMetaORM).filter_by(key="last_hash").first()
            total_row = session.query(AuditChainMetaORM).filter_by(key="total_records").first()

            last_hash = last_hash_row.value if last_hash_row else GENESIS_HASH
            total = int(total_row.value) if total_row else 0

            # Set chain fields
            action.previous_hash = last_hash
            action.chain_sequence = total + 1
            action.record_hash = action.compute_hash()

            # Persist the action
            orm = AgentActionORM(
                action_id=action.action_id,
                timestamp=action.timestamp,
                agent_id=action.agent_id,
                session_id=action.session_id,
                workflow_id=action.workflow_id,
                human_authorizer_id=action.human_authorizer_id,
                human_authorizer_role=action.human_authorizer_role,
                delegation_chain=action.delegation_chain,
                operation=action.operation,
                operation_detail=action.operation_detail,
                resource_type=action.resource_type,
                resource_id=action.resource_id,
                phi_categories=action.phi_categories,
                phi_volume=action.phi_volume,
                data_classification=action.data_classification,
                source_system=action.source_system,
                target_system=action.target_system,
                network_zone=action.network_zone,
                access_justification=action.access_justification,
                minimum_necessary_scope=action.minimum_necessary_scope,
                policy_applied=action.policy_applied,
                encryption_in_transit=action.encryption_in_transit,
                encryption_at_rest=action.encryption_at_rest,
                encryption_algorithm=action.encryption_algorithm,
                fips_validated=action.fips_validated,
                input_hash=action.input_hash,
                output_hash=action.output_hash,
                data_modified=action.data_modified,
                modification_type=action.modification_type,
                status=action.status,
                error_message=action.error_message,
                duration_ms=action.duration_ms,
                previous_hash=action.previous_hash,
                record_hash=action.record_hash,
                chain_sequence=action.chain_sequence,
            )
            session.add(orm)

            # Update chain metadata
            if last_hash_row:
                last_hash_row.value = action.record_hash
            if total_row:
                total_row.value = str(total + 1)

            logger.debug(
                "Stored action %s (seq=%d, agent=%s, op=%s)",
                action.action_id, action.chain_sequence, action.agent_id, action.operation,
            )
        return action.action_id

    def store_actions_batch(self, actions: list[AgentAction]) -> list[str]:
        """
        Store multiple actions sequentially, maintaining chain integrity.

        Each action is chained to the previous one. Actions are stored
        in the order provided — the caller is responsible for ordering.

        Args:
            actions: Ordered list of AgentActions to store.

        Returns:
            List of stored action_ids.
        """
        return [self.store_action(action) for action in actions]

    # ------------------------------------------------------------------
    # Violation Storage
    # ------------------------------------------------------------------

    def store_violation(self, violation: ViolationRecord) -> str:
        """
        Record a detected compliance violation.

        Violations are stored with full evidentiary context to support
        OCR audit response, internal investigation, and CAPA tracking.

        Args:
            violation: The ViolationRecord to store.

        Returns:
            violation_id of the stored record.
        """
        with self._session() as session:
            orm = ViolationRecordORM(
                violation_id=violation.violation_id,
                timestamp=violation.timestamp,
                agent_id=violation.agent_id,
                action_id=violation.action_id,
                violation_type=violation.violation_type,
                hipaa_section=violation.hipaa_section,
                severity=violation.severity,
                severity_score=violation.severity_score,
                description=violation.description,
                evidence=violation.evidence,
                phi_impact=violation.phi_impact,
                patient_count=violation.patient_count,
                status=violation.status,
                remediation_action=violation.remediation_action,
                remediation_owner=violation.remediation_owner,
                remediation_deadline=violation.remediation_deadline,
                resolved_at=violation.resolved_at,
            )
            session.add(orm)
            logger.info(
                "Violation stored: %s [%s] agent=%s",
                violation.violation_type, violation.severity, violation.agent_id,
            )
        return violation.violation_id

    def update_violation_status(
        self,
        violation_id: str,
        status: str,
        resolved_at: Optional[str] = None,
        remediation_action: Optional[str] = None,
    ) -> bool:
        """
        Update the status of an existing violation (e.g., mark remediated).

        Unlike action records, violation status fields ARE mutable to support
        the remediation workflow.

        Args:
            violation_id: The violation to update.
            status: New status ("acknowledged", "remediated", "accepted_risk", "false_positive").
            resolved_at: ISO 8601 resolution timestamp.
            remediation_action: Description of remediation taken.

        Returns:
            True if updated, False if violation not found.
        """
        with self._session() as session:
            orm = session.query(ViolationRecordORM).filter_by(violation_id=violation_id).first()
            if not orm:
                return False
            orm.status = status
            if resolved_at:
                orm.resolved_at = resolved_at
            if remediation_action:
                orm.remediation_action = remediation_action
        return True

    # ------------------------------------------------------------------
    # Compliance Report Storage
    # ------------------------------------------------------------------

    def store_report(self, report: ComplianceReport) -> str:
        """
        Persist a compliance report.

        §164.316(b)(2)(i): Compliance documentation must be retained for 6 years.

        Args:
            report: ComplianceReport to store.

        Returns:
            report_id of the stored record.
        """
        with self._session() as session:
            orm = ComplianceReportORM(
                report_id=report.report_id,
                generated_at=report.generated_at,
                report_period_start=report.report_period_start,
                report_period_end=report.report_period_end,
                organization_name=report.organization_name,
                overall_score=report.overall_score,
                overall_rating=report.overall_rating,
                report_json=report.to_dict(),
            )
            session.add(orm)
        return report.report_id

    # ------------------------------------------------------------------
    # Chain Integrity Verification
    # ------------------------------------------------------------------

    def verify_chain_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify the tamper-evident SHA-256 hash chain across all action records.

        Iterates through all action records in chain_sequence order and verifies:
          1. Each record's record_hash matches SHA-256(record fields)
          2. Each record's previous_hash matches the preceding record's record_hash
          3. Sequence numbers are contiguous (no missing records)

        Any failure indicates tampering, deletion, or database corruption.

        §164.312(b): Tamper-evident log requirement.
        NIST SP 800-92 §3.2: Log integrity verification.

        Returns:
            (is_valid: bool, errors: list[str])
            errors is empty if is_valid=True.
        """
        errors: list[str] = []

        with self._session() as session:
            records = (
                session.query(AgentActionORM)
                .order_by(AgentActionORM.chain_sequence)
                .all()
            )

        if not records:
            return True, []

        previous_hash = GENESIS_HASH
        expected_seq = 1

        for orm in records:
            action = orm.to_dataclass()
            seq = action.chain_sequence

            # Check sequence continuity (no gaps = no deleted records)
            if seq != expected_seq:
                errors.append(
                    f"CHAIN GAP: Expected sequence {expected_seq}, got {seq}. "
                    f"Records may have been deleted (action_id={action.action_id})"
                )
                expected_seq = seq + 1
                continue
            expected_seq += 1

            # Verify previous_hash linkage
            if action.previous_hash != previous_hash:
                errors.append(
                    f"HASH LINK BROKEN at seq {seq} (action_id={action.action_id}): "
                    f"previous_hash={action.previous_hash[:16]}... "
                    f"expected={previous_hash[:16]}..."
                )

            # Verify record_hash
            stored_hash = action.record_hash
            computed_hash = action.compute_hash()
            if stored_hash != computed_hash:
                errors.append(
                    f"RECORD TAMPERED at seq {seq} (action_id={action.action_id}): "
                    f"stored_hash={stored_hash[:16]}... "
                    f"computed_hash={computed_hash[:16]}..."
                )

            previous_hash = stored_hash or computed_hash

        is_valid = len(errors) == 0
        if is_valid:
            logger.info("Chain integrity verified: %d records, all hashes valid", len(records))
        else:
            logger.error("Chain integrity FAILED: %d error(s) detected", len(errors))
        return is_valid, errors

    # ------------------------------------------------------------------
    # Action Queries
    # ------------------------------------------------------------------

    def query_actions(
        self,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        operation: Optional[str] = None,
        status: Optional[str] = None,
        data_classification: Optional[str] = None,
        human_authorizer_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[AgentAction]:
        """
        Query action records with flexible filters.

        All filters are AND-combined. Supports time range queries for
        period-based compliance reports.

        §164.312(b): Audit systems must support examination of activity —
        this query interface enables that examination.

        Args:
            agent_id:            Filter by agent ID
            session_id:          Filter by session ID
            workflow_id:         Filter by workflow ID
            start:               ISO 8601 start of time range (inclusive)
            end:                 ISO 8601 end of time range (inclusive)
            operation:           Filter by operation type
            status:              Filter by action status
            data_classification: Filter by PHI classification
            human_authorizer_id: Filter by authorizing user
            limit:               Max records to return (None = all)
            offset:              Pagination offset

        Returns:
            List of matching AgentAction dataclass instances.
        """
        with self._session() as session:
            q = session.query(AgentActionORM)

            if agent_id:
                q = q.filter(AgentActionORM.agent_id == agent_id)
            if session_id:
                q = q.filter(AgentActionORM.session_id == session_id)
            if workflow_id:
                q = q.filter(AgentActionORM.workflow_id == workflow_id)
            if start:
                q = q.filter(AgentActionORM.timestamp >= start)
            if end:
                q = q.filter(AgentActionORM.timestamp <= end)
            if operation:
                q = q.filter(AgentActionORM.operation == operation)
            if status:
                q = q.filter(AgentActionORM.status == status)
            if data_classification:
                q = q.filter(AgentActionORM.data_classification == data_classification)
            if human_authorizer_id:
                q = q.filter(AgentActionORM.human_authorizer_id == human_authorizer_id)

            q = q.order_by(AgentActionORM.chain_sequence)

            if offset:
                q = q.offset(offset)
            if limit:
                q = q.limit(limit)

            return [row.to_dataclass() for row in q.all()]

    def get_action(self, action_id: str) -> Optional[AgentAction]:
        """Retrieve a single action by ID."""
        with self._session() as session:
            orm = session.query(AgentActionORM).filter_by(action_id=action_id).first()
            return orm.to_dataclass() if orm else None

    def count_actions(
        self,
        agent_id: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> int:
        """Return count of actions matching filters."""
        with self._session() as session:
            q = session.query(func.count(AgentActionORM.action_id))
            if agent_id:
                q = q.filter(AgentActionORM.agent_id == agent_id)
            if start:
                q = q.filter(AgentActionORM.timestamp >= start)
            if end:
                q = q.filter(AgentActionORM.timestamp <= end)
            return q.scalar() or 0

    # ------------------------------------------------------------------
    # Violation Queries
    # ------------------------------------------------------------------

    def query_violations(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        violation_type: Optional[str] = None,
        status: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[ViolationRecord]:
        """Query violation records with flexible filters."""
        with self._session() as session:
            q = session.query(ViolationRecordORM)

            if agent_id:
                q = q.filter(ViolationRecordORM.agent_id == agent_id)
            if severity:
                q = q.filter(ViolationRecordORM.severity == severity)
            if violation_type:
                q = q.filter(ViolationRecordORM.violation_type == violation_type)
            if status:
                q = q.filter(ViolationRecordORM.status == status)
            if start:
                q = q.filter(ViolationRecordORM.timestamp >= start)
            if end:
                q = q.filter(ViolationRecordORM.timestamp <= end)

            q = q.order_by(ViolationRecordORM.timestamp.desc())
            if limit:
                q = q.limit(limit)

            return [row.to_dataclass() for row in q.all()]

    def get_violation_summary(
        self,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """
        Return violation counts grouped by severity and type.

        Used for compliance dashboard and report generation.

        Returns:
            {
              "by_severity": {"critical": 3, "high": 8, ...},
              "by_type": {"unencrypted_phi": 5, ...},
              "by_status": {"open": 10, "remediated": 5, ...},
              "total": 15,
            }
        """
        violations = self.query_violations(start=start, end=end)

        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for v in violations:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
            by_type[v.violation_type] = by_type.get(v.violation_type, 0) + 1
            by_status[v.status] = by_status.get(v.status, 0) + 1

        return {
            "by_severity": by_severity,
            "by_type": by_type,
            "by_status": by_status,
            "total": len(violations),
        }

    # ------------------------------------------------------------------
    # Agent Statistics
    # ------------------------------------------------------------------

    def get_agent_stats(self, agent_id: str) -> dict:
        """
        Return summary statistics for a specific agent.

        Used for per-agent compliance dashboards and risk scoring.

        Returns dict with:
          - total_actions, actions_by_operation, phi_records_total
          - violations_by_severity, open_violations
          - last_action_timestamp, first_action_timestamp
          - encryption_compliance_rate
        """
        actions = self.query_actions(agent_id=agent_id)
        violations = self.query_violations(agent_id=agent_id)

        by_operation: dict[str, int] = {}
        total_phi = 0
        encrypted_phi_actions = 0
        phi_actions = 0

        for a in actions:
            by_operation[a.operation] = by_operation.get(a.operation, 0) + 1
            total_phi += a.phi_volume
            if a.involves_phi:
                phi_actions += 1
                if a.encryption_in_transit and a.encryption_at_rest:
                    encrypted_phi_actions += 1

        by_severity: dict[str, int] = {}
        open_count = 0
        for v in violations:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
            if v.status == "open":
                open_count += 1

        encryption_rate = (
            encrypted_phi_actions / phi_actions if phi_actions > 0 else 1.0
        )

        return {
            "agent_id": agent_id,
            "total_actions": len(actions),
            "actions_by_operation": by_operation,
            "phi_records_total": total_phi,
            "total_violations": len(violations),
            "violations_by_severity": by_severity,
            "open_violations": open_count,
            "first_action_timestamp": actions[0].timestamp if actions else None,
            "last_action_timestamp": actions[-1].timestamp if actions else None,
            "encryption_compliance_rate": round(encryption_rate, 4),
        }

    # ------------------------------------------------------------------
    # Dashboard / reporting helpers
    # ------------------------------------------------------------------

    def get_database_stats(self) -> dict:
        """Return high-level database statistics for the dashboard."""
        with self._session() as session:
            total_actions = session.query(func.count(AgentActionORM.action_id)).scalar() or 0
            total_agents = session.query(func.count(AgentIdentityORM.agent_id)).scalar() or 0
            total_violations = session.query(func.count(ViolationRecordORM.violation_id)).scalar() or 0
            open_violations = (
                session.query(func.count(ViolationRecordORM.violation_id))
                .filter(ViolationRecordORM.status == "open")
                .scalar() or 0
            )
            chain_meta = session.query(AuditChainMetaORM).all()

        meta = {row.key: row.value for row in chain_meta}

        return {
            "total_actions": total_actions,
            "total_agents": total_agents,
            "total_violations": total_violations,
            "open_violations": open_violations,
            "chain_total_records": int(meta.get("total_records", 0)),
            "chain_genesis_hash": meta.get("genesis_hash", ""),
            "chain_last_hash": meta.get("last_hash", "")[:16] + "...",
            "chain_initialized_at": meta.get("chain_initialized_at", ""),
        }

    def get_recent_actions(self, limit: int = 20) -> list[AgentAction]:
        """Return the N most recent actions (newest first)."""
        with self._session() as session:
            rows = (
                session.query(AgentActionORM)
                .order_by(AgentActionORM.chain_sequence.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dataclass() for r in rows]

    def get_critical_violations(self, limit: int = 10) -> list[ViolationRecord]:
        """Return the most recent critical/high open violations."""
        with self._session() as session:
            rows = (
                session.query(ViolationRecordORM)
                .filter(
                    ViolationRecordORM.status == "open",
                    ViolationRecordORM.severity.in_(["critical", "high"]),
                )
                .order_by(ViolationRecordORM.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dataclass() for r in rows]


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
