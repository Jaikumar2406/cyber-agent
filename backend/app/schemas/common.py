"""Shared enums / basic schema vocabulary used across the platform."""

from enum import StrEnum


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POTENTIAL = "POTENTIAL"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanMode(StrEnum):
    MODE_1 = "MODE_1"
    MODE_2 = "MODE_2"
    MODE_3 = "MODE_3"


class ScanStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNREACHABLE = "UNREACHABLE"


class Intensity(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"


class EvidenceSource(StrEnum):
    RUNTIME = "RUNTIME"
    CODE = "CODE"
    CRYPTO = "CRYPTO"
    HARNESS = "HARNESS"


class ToolResultStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    POLICY_DENIED = "POLICY_DENIED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVAL_DENIED = "APPROVAL_DENIED"


class ApprovalState(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class TerminationReason(StrEnum):
    UNKNOWN = "UNKNOWN"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TOOL_FAILURE = "TOOL_FAILURE"
    TIMEOUT = "TIMEOUT"
    COMPLETED = "COMPLETED"