from __future__ import unicode_literals

__all__ = [
    # Exceptions
    "LLRPError",
    "LLRPResponseError",
    "ReaderConfigurationError",
]


class LLRPError(Exception):
    pass


class LLRPResponseError(LLRPError):
    pass


class ReaderConfigurationError(LLRPError):
    pass
