"""LLRP message parent classes and metaclasses.
"""

import construct as cs
import logging
from six import with_metaclass


logger = logging.getLogger(__name__)


class LLRPMessageMeta(type):
    """Metaclass to register LLRPMessage subclasses.
    """
    message_classes = {}

    def __new__(metaname, classname, baseclasses, attrs):
        logger.debug('new message type %r', classname)

        # validate LLRPMessage subclass being defined
        if baseclasses and baseclasses != (object,):  # but skip superclass
            if 'ty' not in attrs:
                raise ValueError("Missing member 'ty'")
            if not isinstance(attrs['ty'], int):
                raise ValueError("Member 'ty' wrong type {}".format(
                    type(attrs['ty'])))

        return type.__new__(metaname, classname, baseclasses, attrs)

    def __init__(classobject, classname, baseclasses, attrs):
        msgtype = attrs['ty']
        LLRPMessageMeta.message_classes[msgtype] = classobject


LLRPMessageHeader = cs.Struct(
    cs.Embedded(cs.BitStruct(
        cs.Padding(3),
        'version' / cs.Const(cs.BitsInteger(3), 2),
        'type' / cs.BitsInteger(10),
    )),
    'length' / cs.Int32ub,
    'message_id' / cs.Int32ub,
)


class LLRPMessage(with_metaclass(LLRPMessageMeta)):
    ty = None
    struct = None
    message_version = 2  # constant
    message_id = 0

    @classmethod
    def next_message_id(cls):
        cls.message_id += 1
        return cls.message_id

    def __init__(self, **kwargs):
        self.fields = dict(**kwargs)

        self._struct = cs.Struct(
            cs.Embedded(LLRPMessageHeader),
        )
        if self.struct:
            self._struct += cs.Embedded(self.struct)

    def length(self):
        return self._struct.sizeof()

    def build(self):
        fields = cs.Container(type=self.ty,
                              length=self.length(),
                              message_id=LLRPMessage.next_message_id(),
                              **self.fields)
        return self._struct.build(fields)
