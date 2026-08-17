"""Domain exceptions for the secret service layer.

These replace the broad ``except Exception`` pattern in route handlers with
specific, catchable errors. Commands raise these; route adapters catch and
format them (flash/redirect or JSON). This keeps error handling consistent
across the UI, ESO, and management API surfaces and stops real bugs from
being swallowed into generic "Could not save the secret" messages.
"""

from __future__ import annotations


class SecretError(Exception):
    """Base class for all secret-service domain errors."""


class SecretNotFound(SecretError):
    """The requested secret does not exist or is not visible to the caller."""


class AuthorizationDenied(SecretError):
    """The caller lacks permission for the requested operation.

    The optional ``status`` attribute lets adapters pick the right HTTP code
    (403 for a permission denial, 401 for an unauthenticated machine path).
    """

    def __init__(self, message: str = "forbidden", *, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


class ValidationError(SecretError):
    """Input failed validation (bad key, kind, expiry, metadata key, etc.)."""


class SecretOperationError(SecretError):
    """An unexpected error occurred during a secret DB operation.

    Wraps the underlying exception so route adapters can log the detail while
    showing the user a generic message.
    """

    def __init__(self, message: str = "Could not save the secret") -> None:
        super().__init__(message)
