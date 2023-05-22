from usr.snmp_common import *


class Length(object):
    INDEFINITE = "indefinite"


class LengthInfo(object):
    def __init__(self, length, offset):
        self.length = length
        self.offset = offset


class ValueMetaData(object):
    def __init__(self, bounds, next_value_index):
        self.bounds = bounds
        self.next_value_index = next_value_index


def get_value_slice(data: bytes, index: int = 0):
    """
    Helper method to extract lightweight information about value locations in
    a data-stream.

    The function returns both a slice at which a value can be found, and the
    index at which the next value can be found.
    """
    length, offset = decode_length(data, index + 1)
    if length == -1:
        start = index + 2
        end = data.find(b"\x00\x00", index)
        nex_index = end + 2
    else:
        start = index + 1 + offset
        end = index + 1 + offset + length
        nex_index = end
    value_slice = (start, end)
    if end > len(data):
        raise X690Error(
            "Invalid Slice %r (data length=%r)" % (value_slice, len(data))
        )
    return value_slice, nex_index


class TypeInfo:

    def __init__(self, cls, nature, tag, _raw_value=None):
        self.cls = cls
        self.nature = nature
        self.tag = tag
        self._raw_value = _raw_value

    @staticmethod
    def from_bytes(data):
        if isinstance(data, (bytes, bytearray)):
            data = int.from_bytes(bytes(data), "big")
        if data == 0b11111111:
            raise NotImplementedError(
                "Long identifier types are not yet " "implemented"
            )
        cls_hint = (data & 0b11000000) >> 6
        pc_hint = (data & 0b00100000) >> 5
        value = data & 0b00011111

        if cls_hint == 0b00:
            cls = TypeClass.UNIVERSAL
        elif cls_hint == 0b01:
            cls = TypeClass.APPLICATION
        elif cls_hint == 0b10:
            cls = TypeClass.CONTEXT
        elif cls_hint == 0b11:
            cls = TypeClass.PRIVATE
        else:
            pass  # Impossible case (2 bits can only have 4 combinations).

        nature = TypeNature.CONSTRUCTED if pc_hint else TypeNature.PRIMITIVE

        instance = TypeInfo(cls, nature, value)
        instance._raw_value = data
        return instance

    def to_bytes(self):
        if self.cls == TypeClass.UNIVERSAL:
            cls = 0b00
        elif self.cls == TypeClass.APPLICATION:
            cls = 0b01
        elif self.cls == TypeClass.CONTEXT:
            cls = 0b10
        elif self.cls == TypeClass.PRIVATE:
            cls = 0b11
        else:
            raise ValueError("Unexpected class for type info")

        if self.nature == TypeNature.CONSTRUCTED:
            nature = 0b01
        elif self.nature == TypeNature.PRIMITIVE:
            nature = 0b00
        else:
            raise ValueError("Unexpected primitive/constructed for type info")

        output = cls << 6 | nature << 5 | self.tag
        return bytes([output])


def decode_length(data, index=0):
    data0 = data[index]
    if data0 == 0b11111111:
        # reserved
        raise NotImplementedError("This is a reserved case in X690")

    if data0 & 0b10000000 == 0:
        # definite short form
        output = int.from_bytes(bytes([data0]), "big")
        offset = 1
    elif data0 ^ 0b10000000 == 0:
        # indefinite form
        output = -1
        offset = -1
    else:
        # definite long form
        num_octets = int.from_bytes(bytes([data0 ^ 0b10000000]), "big")
        value_octets = data[index + 1: index + num_octets + 1]
        output = int.from_bytes(bytes(value_octets), "big")
        offset = num_octets + 1
    return output, offset


def encode_length(value):
    if value == Length.INDEFINITE:  # type: ignore
        return bytes([0b10000000])

    if value < 127:
        return bytes([value])

    output = []
    while value > 0:
        value, remainder = value // 256, value % 256
        output.insert(0, remainder)

    # prefix length information
    output = [0b10000000 | len(output)] + output
    return bytes(output)


def get_slice_data(data, slc):
    if not slc:
        return data
    if len(slc) == 1:
        if slc[0] is None:
            slc[0] = len(data)
        return data[:slc[0]]
    else:
        if slc[0] is None:
            slc[0] = 0
        if slc[1] is None:
            slc[1] = len(data)
        if len(slc) == 2:
            return data[slc[0]:slc[1]]
        else:
            if slc[2] is None:
                return data[slc[0]:slc[1]]
            else:
                return data[slc[0]:slc[1]:slc[2]]


def get_slice_start(slc, default=0):
    if not slc:
        return default
    if len(slc) == 1:
        return default
    else:
        return default if slc[0] is None else slc[0]


def get_slice_end(slc, default=None):
    if not slc:
        return default
    if len(slc) == 1:
        return default if slc[0] is None else slc[0]
    else:
        return default if slc[1] is None else slc[1]


def group_varbinds(varbinds, effective_roots, user_roots=None):
    user_roots = user_roots or []
    n = len(effective_roots)

    results = {}
    for i in range(n):
        results[effective_roots[i]] = varbinds[i::n]

    if user_roots:
        new_results = {}
        for key, value in results.items():
            containment = [base for base in user_roots if key in base]
            if len(containment) > 1:
                raise RuntimeError(
                    "Unexpected OID result. A value was "
                    "contained in more than one base than "
                    "should be possible!"
                )
            if not containment:
                continue
            new_results[containment[0]] = value
            results = new_results

    return results


def get_unfinished_walk_oids(grouped_oids):
    last_received_oids = []
    for k, v in grouped_oids.items():
        if v:
            last_received_oids.append((k, WalkRow(v[-1], v[-1].oid in k)))
    output = []
    for item in last_received_oids:
        if item[1].unfinished:
            output.append(item)
    return output


def deduped_varbinds(requested_oids, grouped_oids, yielded):
    for var in grouped_oids.values():
        for varbind in var:
            containment = [varbind.oid in _ for _ in requested_oids]
            if not any(containment) or varbind.oid in yielded:
                print(
                    "DEBUG Unexpected device response: Returned VarBind %s "
                    "was either not contained in the requested tree or "
                    "appeared more than once. Skipping!" % (varbind)
                )
                continue
            yielded.add(varbind.oid)
            yield varbind


def zip_longest(a, b, fillvalue=None):
    _len = max(len(a), len(b))
    ret = []
    for i in range(_len):
        temp = [fillvalue, fillvalue]
        if i < len(a):
            temp[0] = a[i]
        if i < len(b):
            temp[1] = b[i]
        ret.append(temp)
    return ret


def password_to_key(hash_implementation, padding_length: int):
    def hasher(password: bytes, engine_id: bytes) -> bytes:
        hash_size = 1024 * 1024
        num_words = 1024 // len(password)
        hash_instance = hash_implementation()
        ret = hash_size
        for i in range(num_words + 1):
            if ret - (len(password) * 1024) >= 0:
                hash_instance.update(password * 1024)
                ret -= len(password) * 1024
            else:
                if ret <= 0:
                    break
                else:
                    hash_instance.update((password * 1024)[:ret])
                    ret = 0
                    break
        key = hash_instance.digest()
        localised_buffer = (
                key[:padding_length] + engine_id + key[:padding_length]
        )
        final_key = hash_implementation(localised_buffer).digest()
        return final_key

    return hasher
