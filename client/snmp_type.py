from usr.snmp_utils import *
from usr.snmp_common import *


def decode(data: bytes, start_index: int = 0, enforce_type=None, strict=False):
    if start_index >= len(data):
        raise IndexError("Attempting to read from position {} on data with length {}".format(start_index, len(data)))

    start_index = start_index or 0
    type_ = TypeInfo.from_bytes(data[start_index])
    try:
        cls = X690Type.get(type_.cls, type_.tag, type_.nature)
    except Exception:
        cls = UnknownType

    data_slice, next_tlv = get_value_slice(data, start_index)
    output = cls.from_bytes(data, data_slice)
    if cls is UnknownType:
        output.tag = data[start_index]  # type: ignore

    if enforce_type and not isinstance(output, enforce_type):
        raise UnexpectedType(
            "Unexpected decode result. Expected instance of type {} but got {} instead".format(enforce_type,
                                                                                               type(output)))

    if strict and next_tlv < len(data) - 1:
        remainder = data[next_tlv:]
        raise IncompleteDecoding("Strict decoding still had {} remaining bytes!".format(len(remainder)),
                                 remainder=remainder)

    return output, next_tlv


class _SENTINEL_UNINITIALISED:  # pylint: disable=invalid-name
    """
    Helper for specific sentinel values
    """


#: sentinel value for uninitialised objects (used for lazy decoding)
UNINITIALISED = _SENTINEL_UNINITIALISED()


class X690Type(object):
    __slots__ = ["pyvalue", "_raw_bytes"]
    TYPECLASS: TypeClass = TypeClass.UNIVERSAL
    NATURE = [TypeNature.CONSTRUCTED]
    INIT = False
    TAG: int = -1
    _raw_bytes: bytes
    registry_map: dict = dict()
    bounds = None

    def __init__(self, value=UNINITIALISED):
        self.pyvalue = value
        self._raw_bytes = b""

    @property
    def value(self):
        """
        Returns the value as a pure Python type
        """
        if not isinstance(self.pyvalue, _SENTINEL_UNINITIALISED):
            return self.pyvalue
        return self.decode_raw(self.raw_bytes, self.bounds)

    @property
    def raw_bytes(self) -> bytes:
        if self._raw_bytes != b"":
            return self._raw_bytes
        if self.pyvalue is UNINITIALISED:
            return b""
        self._raw_bytes = self.encode_raw()
        return self._raw_bytes

    @staticmethod
    def decode_raw(data, slc=None):
        return get_slice_data(data, slc)

    @staticmethod
    def get(typeclass, typeid, nature=TypeNature.CONSTRUCTED):
        cls = X690Type.registry_map[(typeclass, typeid, nature)]
        return cls

    @staticmethod
    def register(cls):
        for nature in cls.NATURE:
            X690Type.registry_map[(cls.TYPECLASS, cls.TAG, nature)] = cls

    @staticmethod
    def all():
        return list(X690Type.registry_map.values())

    @classmethod
    def validate(cls, data: bytes) -> None:
        """
        Given a bytes object, checks if the given class *cls* supports decoding
        this object. If not, raises a ValueError.
        """
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != cls.TYPECLASS or tinfo.tag != cls.TAG:
            raise ValueError(
                "Invalid type header! "
                "Expected a %s class with tag "
                "ID 0x%02x, but got a %s class with "
                "tag ID 0x%02x" % (cls.TYPECLASS, cls.TAG, tinfo.cls, data[0])
            )

    @classmethod
    def decode(
            cls, data: bytes
    ):  # pragma: no cover
        """
        This method takes a bytes object which contains the raw content octets
        of the object. That means, the octets *without* the type information
        and length.

        This function must be overridden by the concrete subclasses.
        """
        slc = get_value_slice(data).bounds
        output = cls.decode_raw(data, slc)
        return cls(output)

    @classmethod
    def from_bytes(
            cls, data, slc=None
    ):
        try:
            instance = cls()
        except TypeError as exc:
            raise X690Error(
                "Custom types must have a no-arg constructor allowing "
                "x690.types.UNINITIALISED as value. Custom type %r does not "
                "support this!" % cls
            ) from exc
        instance.raw_bytes = data
        instance.bounds = slc
        return instance

    @property
    def raw_bytes(self):
        if self._raw_bytes != b"":
            return self._raw_bytes
        if self.pyvalue is UNINITIALISED:
            return b""
        self._raw_bytes = self.encode_raw()
        return self._raw_bytes

    @raw_bytes.setter
    def raw_bytes(self, value: bytes) -> None:
        self._raw_bytes = value

    def to_bytes(self) -> bytes:  # pragma: no cover
        if self.bounds is not None:
            value = get_slice_data(self.raw_bytes, self.bounds)
        else:
            value = self.encode_raw()
        tinfo = TypeInfo(self.TYPECLASS, self.NATURE[0], self.TAG)
        return tinfo.to_bytes() + encode_length(len(value)) + value

    def __repr__(self) -> str:
        repr_value = repr(self.value)
        return "%s(value = %s)" % (self.__class__.__name__, repr_value)

    def encode_raw(self):
        if isinstance(self.pyvalue, _SENTINEL_UNINITIALISED):
            return b""
        return self.pyvalue

    def pythonize(self):
        return self.value


class UnknownType(X690Type):
    """
    A fallback type for anything not in X.690.

    Instances of this class contain the raw information as parsed from the
    bytes as the following attributes:

    * ``value``: The value without leading metadata (as bytes value)
    * ``tag``: The *unparsed* "tag". This is the type ID as defined in the
      reference document. See :py:class:`~puresnmp.x690.util.TypeInfo` for
      details.
    * ``typeinfo``: unused (derived from *tag* and only here for consistency
      with ``__repr__`` of this class).
    """

    TAG = 0x99

    def __init__(self, value: bytes = b"", tag: int = -1) -> None:
        super().__init__(value or UNINITIALISED)
        self.tag = tag

    def __repr__(self) -> str:
        typeinfo = TypeInfo.from_bytes(self.tag)
        tinfo = "{}/{}/{}".format(typeinfo.cls, typeinfo.nature, typeinfo.tag)
        return "<{} {} {} {}>".format(self.__class__.__name__, self.tag, self.value, tinfo)

    def __eq__(self, other: object) -> bool:
        return (
                isinstance(other, UnknownType)
                and self.value == other.value
                and self.tag == other.tag
        )


class Boolean(X690Type):
    TAG = 0x01
    NATURE = [TypeNature.PRIMITIVE]

    @staticmethod
    def decode_raw(data, slc=None) -> bool:
        return data[slc] != b"\x00"

    @classmethod
    def validate(cls, data) -> None:
        super().validate(data)
        if data[1] != 1:
            raise ValueError(
                "Unexpected Boolean value. Length should be 1,"
                " it was %d" % data[1]
            )

    def encode_raw(self) -> bytes:
        return b"\x01" if self.pyvalue else b"\x00"

    def __eq__(self, other):
        return isinstance(other, Boolean) and self.value == other.value


class Null(X690Type):
    TAG = 0x05
    NATURE = [TypeNature.PRIMITIVE]

    @classmethod
    def validate(cls, data: bytes) -> None:
        super().validate(data)
        if data[1] != 0:
            raise ValueError(
                "Unexpected NULL value. Length should be 0, it "
                "was %d" % data[1]
            )

    @staticmethod
    def decode_raw(data: bytes, slc: slice = None) -> None:
        return None

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`

        >>> Null().encode_raw()
        b'\\x00'
        """
        # pylint: disable=no-self-use
        return b"\x00"

    def to_bytes(self) -> bytes:
        return b"\x05\x00"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Null) and self.value == other.value

    def __repr__(self) -> str:
        return "Null(value = None)"

    def __bool__(self) -> bool:
        return False

    def __nonzero__(self) -> bool:  # pragma: no cover
        return False


class OctetString(X690Type):
    TAG = 0x04
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    def __init__(
            self, value=b""
    ) -> None:
        if isinstance(value, str):
            value = value.encode()
        if not value:
            value = UNINITIALISED
        super().__init__(value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OctetString) and self.value == other.value


class Sequence(X690Type):
    """
    Represents an X.690 sequence type. Instances of this class are iterable and
    indexable.
    """

    TAG = 0x10

    @staticmethod
    def decode_raw(data: bytes, slc: slice = None):
        start_index = get_slice_start(slc, default=0)
        if not get_slice_data(data, slc) or start_index > len(data):
            return []
        item, next_pos = decode(data, start_index)
        items = [item]
        end = get_slice_end(slc, default=len(data))
        while next_pos < end:
            item, next_pos = decode(data, next_pos)
            items.append(item)
        return items

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, _SENTINEL_UNINITIALISED):
            return b""
        items = []
        for item in self.pyvalue:
            items.append(item.to_bytes())
        output = b"".join(items)
        return output

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sequence):
            return False
        return self.raw_bytes[self.bounds] == other.raw_bytes[other.bounds]

    def __repr__(self) -> str:
        item_repr = list(self)
        return "Sequence(value = %r)" % item_repr

    def __len__(self) -> int:
        return len(self.value)

    def __getitem__(self, idx: int):
        return self.value[idx]

    def pythonize(self):
        """
        Overrides :py:meth:`~.X690Type.pythonize`
        """
        return [obj.pythonize() for obj in self]


class Integer(X690Type):
    SIGNED = True
    TAG = 0x02
    NATURE = [TypeNature.PRIMITIVE]

    @classmethod
    def decode_raw(cls, data: bytes, slc=None) -> int:
        """
        Converts the raw byte-value (without type & length header) into a
        pure Python type

        Overrides :py:meth:`~.X690Type.decode_raw`
        """
        data = get_slice_data(data, slc)
        return int.from_bytes(bytes(data), "big", cls.SIGNED)

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, _SENTINEL_UNINITIALISED):
            return b""
        octets = [self.pyvalue & 0b11111111]

        # Append remaining octets for long integers.
        remainder = self.pyvalue
        while remainder not in (0, -1):
            remainder = remainder >> 8
            octets.append(remainder & 0b11111111)

        if remainder == 0 and octets[-1] == 0b10000000:
            octets.append(0)
        octets.reverse()

        # remove leading octet if there is a string of 9 zeros or ones
        while len(octets) > 1 and (
                (octets[0] == 0 and octets[1] & 0b10000000 == 0)
                or (octets[0] == 0b11111111 and octets[1] & 0b10000000 != 0)
        ):
            del octets[0]
        return bytes(octets)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Integer) and self.value == other.value


class ObjectIdentifier(X690Type):
    TAG = 0x06
    NATURE = [TypeNature.PRIMITIVE]

    def __init__(self, value=UNINITIALISED):
        if (
                not isinstance(value, _SENTINEL_UNINITIALISED)
                and value
                and value.startswith(".")
        ):
            value = value[1:]
        super().__init__(value)

    @property
    def nodes(self):
        if not self.value:
            return tuple()
        return tuple(int(n) for n in self.value.split("."))

    @staticmethod
    def decode_large_value(current_char, stream) -> int:

        """
        If we encounter a value larger than 127, we have to consume from the
        stram until we encounter a value below 127 and recombine them.

        See: https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
        """
        buffer = []
        while current_char > 127:
            buffer.append(current_char ^ 0b10000000)
            current_char = next(stream)
        total = current_char
        for i, digit in enumerate(reversed(buffer)):
            total += digit * 128 ** (i + 1)
        return total

    @staticmethod
    def encode_large_value(value):
        """
        Inverse function of :py:meth:`~.ObjectIdentifier.decode_large_value`
        """
        if value <= 127:
            return [value]
        output = [value & 0b1111111]
        value = value >> 7
        while value:
            output.append(value & 0b1111111 | 0b10000000)
            value = value >> 7
        output.reverse()
        return output

    @staticmethod
    def decode_raw(data: bytes, slc: slice = None):
        """
        Converts the raw byte-value (without type & length header) into a
        pure Python type

        Overrides :py:meth:`~.X690Type.decode_raw`
        """
        # Special case for "empty" object identifiers which should be returned
        # as "0"
        data = get_slice_data(data, slc)
        if not data:
            return ""

        # unpack the first byte into first and second sub-identifiers.
        data0 = data[0]
        first, second = data0 // 40, data0 % 40
        output = [first, second]

        remaining = iter(data[1:])

        for node in remaining:
            # Each node can only contain values from 0-127. Other values need
            # to be combined.
            if node > 127:
                collapsed_value = ObjectIdentifier.decode_large_value(
                    node, remaining
                )
                output.append(collapsed_value)
                continue
            output.append(node)

        instance = ".".join([str(n) for n in output])
        return instance

    def collapse_identifiers(self):
        identifiers = self.nodes
        if len(identifiers) == 0:
            return tuple()

        if len(identifiers) > 1:
            first, second, rest = (
                identifiers[0],
                identifiers[1],
                identifiers[2:],
            )
            first_output = (40 * first) + second
        else:
            first_output = identifiers[0]
            rest = tuple()

        # Values above 127 need a special encoding. They get split up into
        # multiple positions.
        exploded_high_values = []
        for char in rest:
            if char > 127:
                exploded_high_values.extend(
                    ObjectIdentifier.encode_large_value(char)
                )
            else:
                exploded_high_values.append(char)

        collapsed_identifiers = [first_output]
        for subidentifier in rest:
            collapsed_identifiers.extend(
                ObjectIdentifier.encode_large_value(subidentifier)
            )
        return tuple(collapsed_identifiers)

    def encode_raw(self):
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, _SENTINEL_UNINITIALISED):
            return b""
        collapsed_identifiers = self.collapse_identifiers()
        if collapsed_identifiers == ():
            return b""
        try:
            output = bytes(collapsed_identifiers)
        except ValueError as exc:
            raise ValueError(
                "Unable to collapse %r. First two octets are too large!"
                % (self.nodes,)
            ) from exc
        return output

    def __int__(self):
        nodes = self.nodes
        if len(nodes) != 1:
            raise ValueError(
                "Only ObjectIdentifier with one node can be "
                "converted to int. %r is not convertable. It has %d nodes."
                % (self, len(self))
            )
        return nodes[0]

    def __str__(self):
        return "ObjectIdentifier(value = %s)" % (self.value)

    def __repr__(self):
        return "ObjectIdentifier(value = %s)" % (self.value)

    def __eq__(self, other) -> bool:
        return isinstance(other, ObjectIdentifier) and self.value == other.value

    def __len__(self) -> int:
        return len(self.nodes)

    def __contains__(self, other):
        a, b = other.nodes, self.nodes
        if len(a) == len(b):
            return a == b

        if len(b) > len(a):
            return False

        zipped = zip_longest(a, b, fillvalue=None)
        tail = []
        for tmp_a, tmp_b in zipped:
            if tmp_a == tmp_b and not tail:
                continue
            tail.append((tmp_a, tmp_b))

        _, unzipped_b = zip(*tail)
        if all([x is None for x in unzipped_b]):
            return True

        return False

    def __lt__(self, other) -> bool:
        return self.nodes < other.nodes

    def __hash__(self) -> int:
        return hash(self.value)

    def __add__(self, other):
        nodes = ".".join([self.value, other.value])
        return ObjectIdentifier(nodes)

    def __getitem__(self, index):
        if isinstance(index, int):
            return self.nodes[index]
        output = self.nodes[index]
        return ObjectIdentifier(".".join([str(n) for n in output]))

    def parentof(self, other):
        return other in self

    def childof(self, other):
        return self in other


class ObjectDescriptor(X690Type):
    TAG = 0x07
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class External(X690Type):
    TAG = 0x08


class Real(X690Type):
    TAG = 0x09
    NATURE = [TypeNature.PRIMITIVE]


class Enumerated(X690Type):
    TAG = 0x0A
    NATURE = [TypeNature.PRIMITIVE]


class EmbeddedPdv(X690Type):
    TAG = 0x0B


class Utf8String(X690Type):
    TAG = 0x0C
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class RelativeOid(X690Type):
    TAG = 0x0D
    NATURE = [TypeNature.PRIMITIVE]


class Set(X690Type):
    TAG = 0x11


class NumericString(X690Type):
    TAG = 0x12
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class PrintableString(X690Type):
    TAG = 0x13
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class T61String(X690Type):
    TAG = 0x14
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    __INITIALISED = False

    def __init__(self, value="") -> None:
        if isinstance(value, str):
            super().__init__(value or UNINITIALISED)
        else:
            super().__init__(T61String.decode_raw(value))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, T61String) and self.value == other.value

    @staticmethod
    def decode_raw(data: bytes, slc=(None, None)):
        """
        Converts the raw byte-value (without type & length header) into a
        pure Python type

        Overrides :py:meth:`~.X690Type.decode_raw`
        """
        data = data[slc]
        if not T61String.__INITIALISED:
            # t61codec.register()
            T61String.__INITIALISED = True
        return data.decode("t61")

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if not T61String.__INITIALISED:  # pragma: no cover
            # t61codec.register()
            T61String.__INITIALISED = True
        if isinstance(self.pyvalue, _SENTINEL_UNINITIALISED):
            return b""
        return self.pyvalue.encode("t61")


class VideotexString(X690Type):
    TAG = 0x15
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class IA5String(X690Type):
    TAG = 0x16
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class UtcTime(X690Type):
    TAG = 0x17
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class GeneralizedTime(X690Type):
    TAG = 0x18
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class GraphicString(X690Type):
    TAG = 0x19
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    @staticmethod
    def decode_raw(data: bytes, slc: slice = None) -> str:
        data = data[slc]
        return data.decode("ascii")


class VisibleString(X690Type):
    TAG = 0x1A
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class GeneralString(X690Type):
    TAG = 0x1B
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class UniversalString(X690Type):
    TAG = 0x1C
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class CharacterString(X690Type):
    TAG = 0x1D


class BmpString(X690Type):
    TAG = 0x1E
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class EOC(X690Type):
    TAG = 0x00
    NATURE = [TypeNature.PRIMITIVE]


class BitString(X690Type):
    TAG = 0x03
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class Counter64(Integer):
    """
    As defined in RFC 2578
    """

    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x06

    def __init__(
            self, value=UNINITIALISED
    ) -> None:
        if not isinstance(value, _SENTINEL_UNINITIALISED):
            value &= 0xFFFFFFFFFFFFFFFF if value >= 2 ** 64 else value
            if value <= 0:
                value = 0
        super().__init__(value)


class Counter(Integer):
    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x01

    def __init__(
            self, value=UNINITIALISED
    ) -> None:
        if not isinstance(value, _SENTINEL_UNINITIALISED):
            value &= 0xFFFFFFFF if value >= 2 ** 32 else value
            if value <= 0:
                value = 0
        super().__init__(value)


class IpAddress(X690Type):
    NATURE = OctetString.NATURE
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x00

    def encode_raw(self) -> bytes:
        if b"." in self.value:
            self.pyvalue = bytes([int(x) for x in self.value.split(b".")])
        return self.value

    @staticmethod
    def decode_raw(data, slc=None):
        raw_value = get_slice_data(data, slc)
        pyvalue = b".".join([str(x).encode() for x in raw_value])
        return pyvalue  # type: ignore

    def __eq__(self, other: object) -> bool:
        # TODO: no longer necessary in x690 > 0.5.0a4
        return isinstance(other, IpAddress) and self.value == other.value


class Gauge(Integer):
    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x02


class TimeTicks(Integer):
    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x03


class Opaque(OctetString):
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x04


class NsapAddress(Integer):
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x05


class PDU(X690Type):
    """
    The superclass for SNMP Messages (GET, SET, GETNEXT, ...)
    """

    #: The typeclass identifire for type-detection in :py:mod:`x690`
    TYPECLASS = TypeClass.CONTEXT

    #: The tag for type-detection in :py:mod:`x690`
    TAG = 0

    @classmethod
    def decode_raw(cls, data: bytes, slc: slice = None):
        if not data:
            raise EmptyMessage("No data to decode!")
        request_id, nxt = decode(data, get_slice_start(slc, default=0), enforce_type=Integer)
        error_status, nxt = decode(data, nxt, enforce_type=Integer)
        error_index, nxt = decode(data, nxt, enforce_type=Integer)

        if error_status.value:
            error_detail, nxt = decode(data, nxt, enforce_type=Sequence)
            varbinds = [VarBind(oid, value) for oid, value in error_detail]  # type: ignore
            offending_oid = None
            if error_index.value != 0:
                offending_oid = varbinds[error_index.value - 1].oid
            exception = ErrorResponse.construct(
                error_status.value, offending_oid or ObjectIdentifier()
            )
            raise exception

        values, nxt = decode(data, nxt, enforce_type=Sequence)

        if not isinstance(values, Sequence):
            raise TypeError(
                "PDUs can only be decoded from sequences but got "
                "%r instead" % type(values)
            )

        varbinds = []
        for oid, value in values:  # type: ignore
            varbinds.append(VarBind(oid, value))

        return PDUContent(
            request_id.value, varbinds, error_status.value, error_index.value
        )

    def encode_raw(self) -> bytes:

        wrapped_varbinds = [
            Sequence([vb.oid, vb.value]) for vb in self.value.varbinds
        ]
        data = [
            Integer(self.value.request_id),
            Integer(self.value.error_status),
            Integer(self.value.error_index),
            Sequence(wrapped_varbinds),  # type: ignore
        ]
        payload_list = []
        for chunk in data:
            payload_list.append(chunk.to_bytes())
        payload = b"".join(payload_list)
        return payload

    def __repr__(self) -> str:
        try:
            return "%s(%r, %r)" % (
                self.__class__.__name__,
                self.value.request_id,
                self.value.varbinds,
            )
        except:  # pylint: disable=bare-except
            print(
                "ERROR Exception caught in __repr__ of %s", self.__class__.__name__
            )
            return "<{} (error-in repr)>".format(self.__class__.__name__)

    def __eq__(self, other):
        return type(other) == type(self) and self.value == other.value


class NoSuchObject(X690Type):
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 0

    def __init__(
            self,
            value=UNINITIALISED,
    ) -> None:
        if value is UNINITIALISED:
            super().__init__(value=None)
        else:
            super().__init__(value=value)


class NoSuchInstance(X690Type):
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 1

    def __init__(
            self,
            value=UNINITIALISED,
    ) -> None:
        if value is UNINITIALISED:
            super().__init__(value=None)
        else:
            super().__init__(value=value)


class EndOfMibView(X690Type):
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 2

    def __init__(
            self,
            value=UNINITIALISED,
    ) -> None:
        if value is UNINITIALISED:
            super().__init__(value=None)
        else:
            super().__init__(value=value)


class GetRequest(PDU):
    TAG = 0


class GetResponse(PDU):
    TAG = 2


class GetNextRequest(GetRequest):
    TAG = 1


class SetRequest(PDU):
    TAG = 3


class BulkGetRequest(PDU):
    TYPECLASS = TypeClass.CONTEXT
    TAG = 5

    def __init__(self, request_id, non_repeaters, max_repeaters, *oids):
        if len(oids) > MAX_VARBINDS:
            raise TooManyVarbinds(len(oids))
        self.request_id = request_id
        self.non_repeaters = non_repeaters
        self.max_repeaters = max_repeaters
        self.varbinds = []
        for oid in oids:
            self.varbinds.append(VarBind(oid, Null()))
        super().__init__()

    def to_bytes(self) -> bytes:
        wrapped_varbinds = [
            Sequence([vb.oid, vb.value]) for vb in self.varbinds
        ]
        data = [
            Integer(self.request_id),
            Integer(self.non_repeaters),
            Integer(self.max_repeaters),
            Sequence(wrapped_varbinds),  # type: ignore
        ]
        payload = b"".join([chunk.to_bytes() for chunk in data])

        tinfo = TypeInfo(TypeClass.CONTEXT, TypeNature.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return tinfo.to_bytes() + length + payload

    def __repr__(self) -> str:
        try:
            oids = [repr(oid) for oid, _ in self.varbinds]
            return "%s(%r, %r, %r, %s)" % (
                self.__class__.__name__,
                self.request_id,
                self.non_repeaters,
                self.max_repeaters,
                ", ".join(oids),
            )
        except:  # pylint: disable=bare-except
            print("ERROR Exception caught in __repr__ of %s" % (self.__class__.__name__))
            return "<{} (error-in repr)>".format(self.__class__.__name__)

    def __eq__(self, other):
        return (
                type(other) == type(self)
                and self.request_id == other.request_id
                and self.non_repeaters == other.non_repeaters
                and self.max_repeaters == other.max_repeaters
                and self.varbinds == other.varbinds
        )


class InformRequest(PDU):
    TAG = 6


class Trap(PDU):
    TAG = 7

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.source = None


class Report(PDU):
    TAG = 8
