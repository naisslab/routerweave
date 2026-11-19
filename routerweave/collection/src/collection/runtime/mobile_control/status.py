"""Shared status vocabulary for commands, observations, and task outcomes."""

from __future__ import annotations

from enum import StrEnum


class Platform(StrEnum):
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"


class ActionMethod(StrEnum):
    DIRECT = "direct"
    ELEMENT = "element"
    GESTURE = "gesture"
    VISUAL = "visual"


class Idempotency(StrEnum):
    """Retry safety of an action.

    STATE_SETTING means the action expresses a target state, for example
    ``ensure_playing``. REPEATABLE means a bounded at-least-once task such as
    feed scrolling may safely repeat. NON_IDEMPOTENT covers exact toggles and
    relative navigation whose uncertain effect must not be repeated.
    """

    IDEMPOTENT = "idempotent"
    STATE_SETTING = "state_setting"
    REPEATABLE = "repeatable"
    NON_IDEMPOTENT = "non_idempotent"


class CommandStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class ConditionStatus(StrEnum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    UNKNOWN = "unknown"


class OutcomeStatus(StrEnum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    RETRYABLE_FAILURE = "retryable_failure"
    FINAL_FAILURE = "final_failure"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class ObservationLevel(StrEnum):
    FAST = "fast"
    STRUCTURED = "structured"
    VISUAL = "visual"


class FailureKind(StrEnum):
    INVALID_PLAYBOOK = "invalid_playbook"
    OBSERVATION_FAILED = "observation_failed"
    NO_STRATEGY = "no_strategy"
    AMBIGUOUS_TARGET = "ambiguous_target"
    COMMAND_REJECTED = "command_rejected"
    COMMAND_UNCERTAIN = "command_uncertain"
    TRANSITION_TIMEOUT = "transition_timeout"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    RECOVERY_FAILED = "recovery_failed"
    CLEANUP_FAILED = "cleanup_failed"
    INTERRUPTION_BLOCKED = "interruption_blocked"
    SUSTAINMENT_FAILED = "sustainment_failed"
    ACTIVITY_FAILED = "activity_failed"
