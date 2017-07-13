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


GeneralDeviceCapabilities = cs.Struct(
    cs.Embedded(LLRPParamHeader),
    'max_number_of_antenna_supported' / cs.Int16ub,
    'c' / cs.Flag,
    't' / cs.Flag,
    cs.Padding(12),
    'device_manufacturer_name' / cs.Int32ub,
    'model_name' / cs.Int32ub,
    'firmware_version_byte_count' / cs.Int16ub,
    'firmware_version' / cs.String(this.firmware_version_byte_count,
                                   encoding="utf8"),
    #'receive_sensitivity_table' /
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


class SetProtocolVersion(LLRPMessage):
    # 17.1.3 SET_PROTOCOL_VERSION
    ty = 47
    struct = cs.Struct(
        'protocol_version' / cs.Int8ub
    )


class SetProtocolVersionResponse(LLRPMessage):
    # 17.1.4 GET_SUPPORTED_VERSION_RESPONSE
    ty = 57
    struct = cs.Struct(
        'llrp_status' / LLRPStatus
    )


class GetReaderCapabilities(LLRPMessage):
    ty = 1
    struct = cs.Struct(
        'requested_data' / cs.Int8ub,
    )


class GetReaderCapabilitiesResponse(LLRPMessage):
    ty = 11
    struct = cs.Struct(
        'llrp_status' / LLRPStatus,
        'general_device_capabilities' / GeneralDeviceCapabilities,
        #'llrp_capabilities' / LLRPCapabilities,
        #'regulatory_capabilities' / RegulatoryCapabilities,
        #'air_protocol_llrp_capabilities' / AirProtocolLLRPCapabilities
    )
