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

    @classmethod
    def class_for(cls, msgtype):
        return LLRPMessageMeta.message_classes[msgtype]

    def __init__(classobject, classname, baseclasses, attrs):
        msgtype = attrs['ty']
        LLRPMessageMeta.message_classes[msgtype] = classobject

        try:
            msg_struct = attrs['struct']
            classobject._struct = cs.Struct(cs.Embedded(LLRPMessageHeader))
            if msg_struct is not None:
                classobject._struct += cs.Embedded(msg_struct)
        except KeyError:
            pass


LLRPParamHeader = cs.Struct(
    cs.BitStruct(
        cs.Padding(6),
        'type' / cs.BitsInteger(10),
        'length' / cs.Int16ub
    )
)


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
    """Base class for LLRP messages.

    Define a child class like this:

        class MyMessage(LLRPMessage):
            ty = 123

            # optional Struct defining fields
            struct = cs.Struct(
                'foo' / cs.Int8ub,
                ...
            )
    """
    ty = None
    struct = None
    _struct = None

    message_version = 2  # constant
    message_id = 0

    @classmethod
    def next_message_id(cls):
        cls.message_id += 1
        return cls.message_id

    def __init__(self, **kwargs):
        self._container = cs.Container(**kwargs)

    def length(self):
        return self._struct.sizeof()

    def __len__(self):
        return self.length()

    def __getattr__(self, attr):
        return getattr(self._container, attr)

    def build(self):
        """Serialize this message into a byte sequence.
        """
        fields = cs.Container(type=self.ty,
                              length=self.length(),
                              message_id=LLRPMessage.next_message_id(),
                              **self._container)
        return self._struct.build(fields)

    @classmethod
    def from_bytes(cls, msgbytes):
        """Return an instance of this message built from a byte sequence.
        """
        header = LLRPMessageHeader.parse(msgbytes[:10])
        msgclass = LLRPMessageMeta.class_for(header.type)
        if msgclass.struct is not None:
            container = msgclass._struct.parse(msgbytes)
            return msgclass(**container)
        else:
            return msgclass()
