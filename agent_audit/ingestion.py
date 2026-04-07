#!/usr/bin/env python3
"""
Agent action ingestion and normalization engine.

Accepts agent action data from multiple input formats and normalizes them into
validated AgentAction records ready for storage and compliance analysis.

Supported input formats:
  1. Python dict / JSON             — Direct API ingestion
  2. JSON Lines (.jsonl)            — Batch file ingestion
  3. CSV                            — Spreadsheet import
  4. CEF (Common Event Format)      — Syslog / SIEM integration
  5. FHIR R4 AuditEvent             — Healthcare-native HL7 FHIR format

HIPAA grounding:
  §164.312(b) — Audit Controls: records must be created at point of action
  §164.312(d) — Entity Authentication: human_authorizer must be present
  §164.502(b) — Minimum Necessary: phi_categories and scope must be captured
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import (
    ALLOWED_OPERATIONS,
    GENESIS_HASH,
    MIN_DELEGATION_CHAIN_LENGTH,
    PHI_CATEGORIES,
    REQUIRED_ACTION_FIELDS,
)
from .models import AgentAction, AgentIdentity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PHI Category Normalization Map
# Maps common synonyms / vendor-specific labels to the canonical taxonomy
# ---------------------------------------------------------------------------

_PHI_SYNONYM_MAP: dict[str, str] = {
    # Demographics / identifiers
    "name": "demographics",
    "patient_name": "demographics",
    "full_name": "demographics",
    "first_name": "demographics",
    "last_name": "demographics",
    "gender": "demographics",
    "sex": "demographics",
    "race": "demographics",
    "ethnicity": "demographics",
    "geographic": "address",
    "zip": "address",
    "zipcode": "address",
    "zip_code": "address",
    "street": "address",
    "city": "address",
    "state": "address",
    "birth_date": "dob",
    "birthdate": "dob",
    "date_of_birth": "dob",
    "age": "dob",
    "telephone": "phone",
    "phone_number": "phone",
    "cell": "phone",
    "mobile": "phone",
    "fax_number": "fax",
    "email_address": "email",
    "social_security": "ssn",
    "social_security_number": "ssn",
    "medical_record": "mrn",
    "medical_record_number": "mrn",
    "patient_id": "mrn",
    "account": "account_number",
    "health_plan_number": "account_number",
    "license": "certificate",
    "device_serial": "device_id",
    "url": "web_url",
    "website": "web_url",
    "ip": "ip_address",
    "fingerprint": "biometric",
    "photograph": "photo",
    "picture": "photo",
    # Clinical
    "icd": "diagnosis",
    "icd10": "diagnosis",
    "dx": "diagnosis",
    "problem_list": "diagnosis",
    "medication": "medications",
    "drug": "medications",
    "prescription": "medications",
    "rx": "medications",
    "labs": "lab_values",
    "lab_result": "lab_values",
    "laboratory": "lab_values",
    "vital": "vitals",
    "vital_signs": "vitals",
    "bp": "vitals",
    "cpt": "procedures",
    "procedure": "procedures",
    "surgery": "procedures",
    "payer": "insurance",
    "insurance_info": "insurance",
    "radiology": "imaging",
    "imaging_study": "imaging",
    "xray": "imaging",
    "mri": "imaging",
    "ct_scan": "imaging",
    "genetic": "genomics",
    "dna": "genomics",
    "psych": "mental_health",
    "behavioral_health": "mental_health",
    "psychiatric": "mental_health",
    "substance": "substance_use",
    "alcohol": "substance_use",
    "drug_use": "substance_use",
}


def _normalize_phi_category(raw: str) -> str:
    """Map a raw PHI category label to the canonical taxonomy."""
    normalized = raw.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized in PHI_CATEGORIES:
        return normalized
    if normalized in _PHI_SYNONYM_MAP:
        return _PHI_SYNONYM_MAP[normalized]
    logger.debug("Unknown PHI category '%s', keeping as-is", raw)
    return normalized


# ---------------------------------------------------------------------------
# ActionIngester
# ---------------------------------------------------------------------------

class ActionIngester:
    """
    Normalizes and validates incoming agent action data from multiple sources.

    Acts as the ingestion gateway: every record entering the audit trail passes
    through this class to ensure it meets HIPAA §164.312(b) completeness
    requirements before being handed to AuditStore.

    Usage::

        ingester = ActionIngester(known_agent_ids={"agent-001", "agent-002"})
        action = ingester.ingest_action(raw_dict)
        errors = ingester.validate_action(action)
    """

    def __init__(
        self,
        known_agent_ids: Optional[set[str]] = None,
        strict_mode: bool = False,
    ) -> None:
        """
        Initialize the ingester.

        Args:
            known_agent_ids: Set of registered agent IDs. When provided, actions
                             referencing unknown agents trigger a validation warning
                             (potential shadow agent — V-015).
            strict_mode:     If True, raise ValueError on any validation error
                             instead of logging and continuing.
        """
        self.known_agent_ids: set[str] = known_agent_ids or set()
        self.strict_mode = strict_mode

    # ------------------------------------------------------------------
    # Public: Single action ingestion
    # ------------------------------------------------------------------

    def ingest_action(self, raw_action: dict) -> AgentAction:
        """
        Normalize and validate a single agent action from a raw dict/JSON object.

        Applies field normalization, fills sensible defaults, computes the
        record hash for tamper-evidence, and validates against HIPAA requirements.

        §164.312(b): Every record must contain agent identity, operation,
        PHI scope, timestamp, and human authorizer before being stored.

        Args:
            raw_action: Raw dict from API, JSON, or other source.

        Returns:
            Normalized AgentAction with computed record_hash.

        Raises:
            ValueError: If strict_mode=True and validation errors are found.
        """
        normalized = self._normalize_dict(raw_action)
        action = self._dict_to_action(normalized)
        errors = self.validate_action(action)
        if errors:
            msg = f"Validation errors for action {action.action_id}: {errors}"
            if self.strict_mode:
                raise ValueError(msg)
            logger.warning(msg)
        # Compute integrity hash (record_hash set after normalization)
        action.record_hash = action.compute_hash()
        return action

    # ------------------------------------------------------------------
    # Public: Batch ingestion
    # ------------------------------------------------------------------

    def ingest_batch(
        self,
        filepath: Path | str,
        fmt: str = "jsonl",
    ) -> list[AgentAction]:
        """
        Ingest a batch of actions from a file.

        Supported formats: "jsonl", "json", "csv", "cef"

        §164.312(b): Batch ingestion supports retroactive loading of audit
        records from systems that buffer locally before central submission.

        Args:
            filepath: Path to the input file.
            fmt:      File format — "jsonl", "json", "csv", or "cef".

        Returns:
            List of normalized AgentAction records.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Batch file not found: {filepath}")

        actions: list[AgentAction] = []
        fmt = fmt.lower().strip()

        if fmt in {"jsonl", "ndjson"}:
            actions = self._ingest_jsonl(filepath)
        elif fmt == "json":
            actions = self._ingest_json_array(filepath)
        elif fmt == "csv":
            actions = self._ingest_csv(filepath)
        elif fmt in {"cef", "syslog"}:
            actions = self._ingest_cef_file(filepath)
        else:
            raise ValueError(f"Unsupported batch format: '{fmt}'. Use jsonl, json, csv, or cef.")

        logger.info("Ingested %d actions from %s (format=%s)", len(actions), filepath, fmt)
        return actions

    # ------------------------------------------------------------------
    # Public: FHIR R4 AuditEvent ingestion
    # HL7 FHIR R4 AuditEvent resource → AgentAction
    # ------------------------------------------------------------------

    def ingest_fhir_audit_event(self, fhir_event: dict) -> AgentAction:
        """
        Parse an HL7 FHIR R4 AuditEvent resource into an AgentAction.

        Maps FHIR AuditEvent fields to AgentAction fields following the
        FHIR R4 AuditEvent resource specification (https://hl7.org/fhir/R4/auditevent.html).

        Field mapping:
          AuditEvent.id            → action_id
          AuditEvent.recorded      → timestamp
          AuditEvent.agent[0].who  → human_authorizer_id
          AuditEvent.agent[1].who  → agent_id
          AuditEvent.entity        → resource_type, resource_id, phi_categories
          AuditEvent.action        → operation
          AuditEvent.outcome       → status
          AuditEvent.source        → source_system

        §164.312(b): FHIR AuditEvent is a healthcare-native format used by
        EHR systems (Epic, Cerner) for access logging. Ingesting these events
        allows the audit tool to correlate agent actions with EHR audit trails.

        Args:
            fhir_event: Parsed FHIR R4 AuditEvent JSON object.

        Returns:
            Normalized AgentAction.
        """
        if fhir_event.get("resourceType") != "AuditEvent":
            raise ValueError(
                f"Expected resourceType='AuditEvent', got '{fhir_event.get('resourceType')}'"
            )

        raw: dict = {}

        # action_id
        raw["action_id"] = fhir_event.get("id") or str(uuid.uuid4())

        # timestamp
        raw["timestamp"] = fhir_event.get("recorded") or _utc_now()

        # operation: FHIR action codes → our operation vocabulary
        fhir_action = fhir_event.get("action", "R")
        raw["operation"] = _fhir_action_to_operation(fhir_action)

        # outcome → status
        outcome = fhir_event.get("outcome", "0")
        raw["status"] = "completed" if outcome == "0" else "failed"
        raw["error_message"] = fhir_event.get("outcomeDesc", "")

        # source system
        source = fhir_event.get("source", {})
        raw["source_system"] = (
            source.get("observer", {}).get("display")
            or source.get("site", "")
            or "FHIR Source"
        )

        # Agents: FHIR splits requestor (human) and agent (system)
        agents = fhir_event.get("agent", [])
        human_agents = [a for a in agents if a.get("requestor", False)]
        system_agents = [a for a in agents if not a.get("requestor", False)]

        if human_agents:
            who = human_agents[0].get("who", {})
            raw["human_authorizer_id"] = (
                who.get("identifier", {}).get("value")
                or who.get("display")
                or "unknown_authorizer"
            )
            raw["human_authorizer_role"] = (
                human_agents[0].get("role", [{}])[0]
                .get("coding", [{}])[0]
                .get("display", "Unknown Role")
                if human_agents[0].get("role")
                else "Unknown Role"
            )
        else:
            raw["human_authorizer_id"] = "unknown_authorizer"
            raw["human_authorizer_role"] = "Unknown"

        if system_agents:
            who = system_agents[0].get("who", {})
            raw["agent_id"] = (
                who.get("identifier", {}).get("value")
                or who.get("display")
                or "unknown_agent"
            )
            raw["agent_name"] = who.get("display", "Unknown Agent")
        else:
            raw["agent_id"] = "unknown_agent"

        # Delegation chain from all agents
        chain = []
        for ag in agents:
            who = ag.get("who", {})
            name = who.get("display") or who.get("identifier", {}).get("value", "unknown")
            chain.append(name)
        raw["delegation_chain"] = chain

        # Entities (PHI resources accessed)
        entities = fhir_event.get("entity", [])
        if entities:
            entity = entities[0]
            what = entity.get("what", {})
            raw["resource_type"] = what.get("type", {}).get("display", "patient_record").lower()
            raw["resource_id"] = what.get("reference") or what.get("identifier", {}).get("value", "")
            # Map FHIR entity type codes to PHI categories
            raw["phi_categories"] = _fhir_entity_to_phi_categories(entities)
            raw["phi_volume"] = len(entities)

        # session / workflow from extension or correlation
        raw["session_id"] = fhir_event.get("session_id") or str(uuid.uuid4())
        raw["workflow_id"] = fhir_event.get("workflow_id") or raw["session_id"]

        return self.ingest_action(raw)

    # ------------------------------------------------------------------
    # Public: CEF (Common Event Format) ingestion
    # ------------------------------------------------------------------

    def ingest_cef(self, cef_line: str) -> AgentAction:
        """
        Parse a CEF (Common Event Format) syslog line into an AgentAction.

        CEF is a standard used by ArcSight, Splunk, and many SIEMs.
        Format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extensions

        HIPAA context: Many healthcare security tools emit CEF-formatted logs.
        This method allows the audit tool to ingest those logs directly,
        correlating them with agent-specific audit records.

        Args:
            cef_line: A single CEF-formatted syslog line.

        Returns:
            Normalized AgentAction.
        """
        cef_line = cef_line.strip()

        # Strip syslog header if present (e.g., "Apr  7 12:00:00 hostname ")
        cef_match = re.search(r"CEF:\d+\|", cef_line)
        if not cef_match:
            raise ValueError(f"Input does not appear to be valid CEF format: {cef_line[:80]}")
        cef_line = cef_line[cef_match.start():]

        # Split fixed fields
        parts = cef_line.split("|", 8)
        if len(parts) < 8:
            raise ValueError(f"CEF line has fewer than 8 pipe-separated fields: {cef_line[:80]}")

        raw: dict = {}
        raw["source_system"] = f"{parts[1]} {parts[2]} {parts[3]}".strip()
        raw["operation_detail"] = parts[5]  # CEF Name field

        # CEF severity (0–10) → our severity taxonomy
        cef_severity = int(parts[6]) if parts[6].isdigit() else 5

        # Parse CEF extensions (key=value pairs, values may be quoted)
        extensions = _parse_cef_extensions(parts[7])

        raw["action_id"] = extensions.get("deviceExternalId") or str(uuid.uuid4())
        raw["timestamp"] = extensions.get("rt") or extensions.get("end") or _utc_now()
        raw["agent_id"] = (
            extensions.get("duid")
            or extensions.get("sproc")
            or extensions.get("deviceProcessName")
            or "unknown_agent"
        )
        raw["human_authorizer_id"] = (
            extensions.get("suid")
            or extensions.get("suser")
            or extensions.get("requestClientApplication")
            or "unknown_authorizer"
        )
        raw["human_authorizer_role"] = extensions.get("sntdom", "Unknown Role")
        raw["operation"] = _map_cef_to_operation(extensions, parts[5])
        raw["resource_type"] = extensions.get("cs1", "patient_record")
        raw["resource_id"] = extensions.get("fname") or extensions.get("fileId", "")
        raw["source_system"] = extensions.get("dhost") or raw["source_system"]
        raw["target_system"] = extensions.get("dst") or extensions.get("destinationServiceName", "")
        raw["network_zone"] = "internal_clinical"
        raw["session_id"] = extensions.get("cs2") or str(uuid.uuid4())
        raw["workflow_id"] = extensions.get("cs3") or raw["session_id"]
        raw["delegation_chain"] = [
            raw["human_authorizer_id"],
            raw["agent_id"],
        ]
        raw["phi_categories"] = ["phi"]
        raw["data_classification"] = "phi"
        raw["status"] = "completed" if cef_severity < 7 else "failed"
        raw["duration_ms"] = int(extensions.get("cn1", 0))

        return self.ingest_action(raw)

    # ------------------------------------------------------------------
    # Public: Validation
    # ------------------------------------------------------------------

    def validate_action(self, action: AgentAction) -> list[str]:
        """
        Validate an AgentAction against HIPAA §164.312 requirements.

        Returns a list of validation error strings. Empty list = valid.

        Checks:
          - Required fields present and non-empty
          - agent_id matches a registered agent (if known_agent_ids provided)
          - human_authorizer_id is non-empty (§164.312(d))
          - timestamp is valid ISO 8601 with timezone
          - operation is from the allowed vocabulary
          - delegation_chain meets minimum length requirement
          - encryption fields present when PHI is accessed
          - phi_categories use canonical taxonomy

        Args:
            action: The AgentAction to validate.

        Returns:
            List of validation error messages.
        """
        errors: list[str] = []

        # Required fields
        for field_name in REQUIRED_ACTION_FIELDS:
            val = getattr(action, field_name, None)
            if not val and val != 0:
                errors.append(f"REQUIRED FIELD MISSING: '{field_name}' is empty or absent")

        # §164.312(d) — Human authorizer must be linked
        if not action.human_authorizer_id or action.human_authorizer_id == "unknown_authorizer":
            errors.append(
                "HIPAA §164.312(d): human_authorizer_id is missing. "
                "Every agent action must be traceable to an authenticated human."
            )

        # Timestamp validation
        ts_error = _validate_timestamp(action.timestamp)
        if ts_error:
            errors.append(f"TIMESTAMP: {ts_error}")

        # Operation vocabulary
        if action.operation not in ALLOWED_OPERATIONS:
            errors.append(
                f"OPERATION: '{action.operation}' is not in the allowed vocabulary. "
                f"Use one of: {sorted(ALLOWED_OPERATIONS)}"
            )

        # §164.312(d) — Delegation chain minimum length
        if len(action.delegation_chain) < MIN_DELEGATION_CHAIN_LENGTH:
            errors.append(
                f"HIPAA §164.312(d): delegation_chain must have at least "
                f"{MIN_DELEGATION_CHAIN_LENGTH} entries (human + agent). "
                f"Got {len(action.delegation_chain)}."
            )

        # 2025 amendment: encryption mandatory when PHI is accessed
        if action.involves_phi:
            if not action.encryption_in_transit:
                errors.append(
                    "HIPAA §164.312(e)(2)(ii) [2025 MANDATORY]: "
                    "PHI is accessed but encryption_in_transit=False. "
                    "Per 2025 amendments, encryption is now required (not addressable)."
                )
            if not action.encryption_at_rest:
                errors.append(
                    "HIPAA §164.312(a)(2)(iv) [2025 MANDATORY]: "
                    "PHI is accessed but encryption_at_rest=False."
                )

        # PHI categories taxonomy check
        unknown_categories = [
            c for c in action.phi_categories
            if c not in PHI_CATEGORIES and c not in {"phi", "limited_dataset", "de_identified"}
        ]
        if unknown_categories:
            errors.append(
                f"PHI_CATEGORIES: Unknown categories {unknown_categories}. "
                f"Use canonical taxonomy from config.PHI_CATEGORIES."
            )

        # Shadow agent detection
        if self.known_agent_ids and action.agent_id not in self.known_agent_ids:
            errors.append(
                f"SHADOW AGENT [V-015]: agent_id '{action.agent_id}' is not in the "
                f"registered agent inventory. This may indicate an unmanaged agent."
            )

        return errors

    # ------------------------------------------------------------------
    # Public: PHI category normalization
    # ------------------------------------------------------------------

    def normalize_phi_categories(self, raw_categories: list[str]) -> list[str]:
        """
        Normalize a list of raw PHI category labels to the canonical taxonomy.

        Handles synonyms, alternate spellings, and vendor-specific labels.
        Deduplicates the result.

        Args:
            raw_categories: Raw category labels from source system.

        Returns:
            Deduplicated list of canonical PHI category strings.
        """
        normalized = [_normalize_phi_category(c) for c in raw_categories]
        seen: set[str] = set()
        result: list[str] = []
        for c in normalized:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result

    # ------------------------------------------------------------------
    # Public: Integrity hash
    # ------------------------------------------------------------------

    def compute_integrity_hash(self, action: AgentAction) -> str:
        """
        Compute the SHA-256 integrity hash for an AgentAction.

        This hash is stored as record_hash and linked into the chain via
        the next record's previous_hash field, implementing the tamper-evident
        append-only log required by §164.312(b).

        Args:
            action: The AgentAction to hash.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        return action.compute_hash()

    # ------------------------------------------------------------------
    # Private: Format-specific parsers
    # ------------------------------------------------------------------

    def _ingest_jsonl(self, filepath: Path) -> list[AgentAction]:
        """Ingest JSON Lines file (one JSON object per line)."""
        actions: list[AgentAction] = []
        with filepath.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    raw = json.loads(line)
                    actions.append(self.ingest_action(raw))
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.error("JSONL line %d parse error: %s", line_num, exc)
        return actions

    def _ingest_json_array(self, filepath: Path) -> list[AgentAction]:
        """Ingest a JSON array file."""
        with filepath.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise ValueError("JSON file must contain an array or a single object.")
        return [self.ingest_action(item) for item in data]

    def _ingest_csv(self, filepath: Path) -> list[AgentAction]:
        """Ingest a CSV file where column headers match AgentAction field names."""
        actions: list[AgentAction] = []
        with filepath.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row_num, row in enumerate(reader, 1):
                try:
                    # JSON-decode list/dict fields stored as strings
                    parsed_row = {}
                    for k, v in row.items():
                        if v and v.startswith(("[", "{")):
                            try:
                                parsed_row[k] = json.loads(v)
                            except json.JSONDecodeError:
                                parsed_row[k] = v
                        else:
                            parsed_row[k] = v
                    actions.append(self.ingest_action(parsed_row))
                except ValueError as exc:
                    logger.error("CSV row %d error: %s", row_num, exc)
        return actions

    def _ingest_cef_file(self, filepath: Path) -> list[AgentAction]:
        """Ingest a file of CEF-formatted syslog lines (one per line)."""
        actions: list[AgentAction] = []
        with filepath.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    actions.append(self.ingest_cef(line))
                except ValueError as exc:
                    logger.error("CEF line %d error: %s", line_num, exc)
        return actions

    # ------------------------------------------------------------------
    # Private: dict normalization helpers
    # ------------------------------------------------------------------

    def _normalize_dict(self, raw: dict) -> dict:
        """
        Apply field-level normalization to a raw action dict.
        Fills defaults, strips whitespace, normalizes enumerations.
        """
        d = dict(raw)  # shallow copy

        # IDs — ensure present
        if not d.get("action_id"):
            d["action_id"] = str(uuid.uuid4())
        if not d.get("session_id"):
            d["session_id"] = str(uuid.uuid4())
        if not d.get("workflow_id"):
            d["workflow_id"] = d["session_id"]

        # Timestamp
        if not d.get("timestamp"):
            d["timestamp"] = _utc_now()
        else:
            d["timestamp"] = _normalize_timestamp(d["timestamp"])

        # Operation: lowercase and map synonyms
        op = str(d.get("operation", "read")).lower().strip()
        d["operation"] = _normalize_operation(op)

        # Status
        d["status"] = str(d.get("status", "completed")).lower().strip()

        # Booleans — handle string representations
        for bool_field in ("encryption_in_transit", "encryption_at_rest", "data_modified", "fips_validated"):
            if bool_field in d:
                d[bool_field] = _to_bool(d[bool_field])
            else:
                d[bool_field] = True if bool_field.startswith("encryption") else False

        # Lists — ensure list type
        for list_field in ("phi_categories", "delegation_chain"):
            val = d.get(list_field, [])
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except json.JSONDecodeError:
                    val = [v.strip() for v in val.split(",") if v.strip()]
            d[list_field] = val

        # Normalize PHI categories
        if d.get("phi_categories"):
            d["phi_categories"] = self.normalize_phi_categories(d["phi_categories"])

        # Integer fields
        for int_field in ("phi_volume", "duration_ms", "chain_sequence"):
            if int_field in d:
                try:
                    d[int_field] = int(d[int_field])
                except (ValueError, TypeError):
                    d[int_field] = 0

        # Default encryption algorithm
        if not d.get("encryption_algorithm"):
            d["encryption_algorithm"] = "AES-256-GCM" if d.get("encryption_in_transit") else "none"

        # Data classification default
        if not d.get("data_classification"):
            d["data_classification"] = "phi" if d.get("phi_categories") else "non_phi"

        # Modification type default
        if not d.get("modification_type"):
            d["modification_type"] = "none"

        # Hash chain defaults
        if not d.get("previous_hash"):
            d["previous_hash"] = GENESIS_HASH
        d["record_hash"] = ""  # Will be computed after normalization

        return d

    def _dict_to_action(self, d: dict) -> AgentAction:
        """Convert a normalized dict to an AgentAction dataclass."""
        # Extract only fields that AgentAction accepts
        import inspect
        from dataclasses import fields as dc_fields
        valid_keys = {f.name for f in dc_fields(AgentAction)}
        filtered = {k: v for k, v in d.items() if k in valid_keys}
        return AgentAction(**filtered)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _normalize_timestamp(ts: str) -> str:
    """
    Normalize a timestamp to ISO 8601 format with UTC timezone.

    HIPAA §164.312(b) requires tamper-evident timestamps. Inconsistent
    timestamp formats across source systems are normalized here.
    """
    ts = str(ts).strip()
    # If already valid ISO 8601 with tz, return as-is
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            # Assume UTC if no timezone provided
            dt = dt.replace(tzinfo=timezone.utc)
            logger.debug("No timezone in timestamp '%s', assuming UTC", ts)
        return dt.isoformat()
    except ValueError:
        pass

    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    # Last resort: millisecond epoch
    try:
        epoch_ms = float(ts)
        dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        return dt.isoformat()
    except ValueError:
        pass

    # Cannot parse — return as-is and let validation catch it
    logger.warning("Could not normalize timestamp: '%s'", ts)
    return ts


def _validate_timestamp(ts: str) -> str:
    """Return error message if timestamp is invalid, else empty string."""
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            return f"Timestamp '{ts}' lacks timezone. HIPAA requires timezone-aware timestamps."
        return ""
    except ValueError:
        return f"Invalid ISO 8601 timestamp: '{ts}'"


def _normalize_operation(op: str) -> str:
    """Map common operation synonyms to canonical vocabulary."""
    synonyms = {
        "get": "read",
        "fetch": "read",
        "view": "read",
        "access": "read",
        "retrieve": "read",
        "post": "write",
        "put": "write",
        "patch": "write",
        "update": "write",
        "create": "write",
        "insert": "write",
        "remove": "delete",
        "erase": "delete",
        "purge": "delete",
        "send": "transmit",
        "export": "transmit",
        "import": "upload",
        "ingest": "upload",
        "convert": "transform",
        "summarize": "summarize",
        "predict": "classify",
        "score": "classify",
        "login": "authenticate",
        "auth": "authenticate",
    }
    return synonyms.get(op, op)


def _to_bool(val) -> bool:
    """Convert various truthy representations to Python bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    return str(val).lower().strip() in {"true", "1", "yes", "y", "on"}


def _fhir_action_to_operation(fhir_action: str) -> str:
    """
    Map FHIR AuditEvent.action codes to AgentAction.operation vocabulary.

    FHIR R4 AuditEvent.action value set:
      C = Create, R = Read/View/Print/Query, U = Update, D = Delete, E = Execute
    """
    mapping = {
        "C": "write",
        "R": "read",
        "U": "write",
        "D": "delete",
        "E": "query",
    }
    return mapping.get(fhir_action.upper(), "read")


def _fhir_entity_to_phi_categories(entities: list[dict]) -> list[str]:
    """
    Extract PHI categories from FHIR AuditEvent entity objects.

    Maps FHIR entity type codes (from FHIR R4 AuditEventEntityType value set)
    to canonical PHI taxonomy.
    """
    categories: set[str] = set()
    type_map = {
        "1": "demographics",      # Person
        "2": "imaging",           # System Object
        "4": "diagnosis",         # Other — treat as clinical
        "Patient": "demographics",
        "Observation": "lab_values",
        "MedicationRequest": "medications",
        "DiagnosticReport": "lab_values",
        "Condition": "diagnosis",
        "Procedure": "procedures",
        "Claim": "insurance",
        "Coverage": "insurance",
        "ImagingStudy": "imaging",
    }
    for entity in entities:
        type_info = entity.get("type", {})
        code = type_info.get("code", "")
        mapped = type_map.get(code, "phi")
        categories.add(mapped)
        # Also check role
        role = entity.get("role", {}).get("code", "")
        if role in type_map:
            categories.add(type_map[role])
    return list(categories) if categories else ["phi"]


def _parse_cef_extensions(ext_str: str) -> dict[str, str]:
    """
    Parse CEF extension string into key-value dict.

    CEF extension format: key=value key2=value2
    Values may contain spaces if the key is a known long-value key (cs1Label etc.)
    """
    result: dict[str, str] = {}
    # Regex: key=value where value ends before next key= or end of string
    pattern = re.compile(r"(\w+)=((?:(?!\s\w+=).)*)", re.DOTALL)
    for match in pattern.finditer(ext_str):
        result[match.group(1)] = match.group(2).strip()
    return result


def _map_cef_to_operation(extensions: dict[str, str], cef_name: str) -> str:
    """
    Map CEF event to an AgentAction operation based on name and extensions.
    """
    name_lower = cef_name.lower()
    if any(kw in name_lower for kw in ("read", "view", "access", "query", "search")):
        return "read"
    if any(kw in name_lower for kw in ("write", "create", "update", "modify")):
        return "write"
    if any(kw in name_lower for kw in ("delete", "remove", "purge")):
        return "delete"
    if any(kw in name_lower for kw in ("upload", "import")):
        return "upload"
    if any(kw in name_lower for kw in ("download", "export", "transmit", "send")):
        return "transmit"
    return "read"
