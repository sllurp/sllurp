from .base import LLRPMessage, LLRPParamHeader
import construct as cs
from construct.expr import this


LLRPStatus = cs.Struct(
    cs.Embedded(LLRPParamHeader),
    'error_description_byte_count' / cs.Int16ub,
    'error_description' / cs.If(this.error_description_byte_count > 0,
                                cs.String(this.error_description_byte_count)),
    'field_error' / cs.Optional(cs.Struct(
        'field_num' / cs.Int16ub,
        'error_code' / cs.Int16ub,
    )),
    'parameter_error' / cs.Optional(cs.Struct(
        'parameter_type' / cs.Int16ub,
        'error_code' / cs.Int16ub,
    )),
)


class GetSupportedVersion(LLRPMessage):
    # 17.1.1 GET_SUPPORTED_VERSION
    ty = 46


class GetSupportedVersionResponse(LLRPMessage):
    # 17.1.2 GET_SUPPORTED_VERSION_RESPONSE
    ty = 56
    struct = cs.Struct(
        'current_version' / cs.Int8ub,
        'supported_version' / cs.Int8ub,
        'llrp_status' / LLRPStatus
    )


class GetReaderCapabilities(LLRPMessage):
    ty = 1
    struct = cs.Struct(
        'requested_data' / cs.Int8ub,
    )
