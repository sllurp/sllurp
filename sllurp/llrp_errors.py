__all__ = [
    # Exceptions
    "LLRPError",
    "LLRPResponseError",
]


class LLRPError (Exception):
    pass


class LLRPResponseError (LLRPError):
    pass
