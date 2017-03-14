from .base import LLRPMessage
import construct as cs


class GetSupportedVersion(LLRPMessage):
    # 17.1.1 GET_SUPPORTED_VERSION
    ty = 46


class GetReaderCapabilities(LLRPMessage):
    ty = 1
    struct = cs.Struct(
        'requested_data' / cs.Int8ub,
    )
