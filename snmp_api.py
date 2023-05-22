import utime as time
import uhashlib as hashlib
from usr.snmp_type import *
from usr.snmp_utils import *
import usocket as socket


def udp_send(endpoint, packet, timeout, loop=None, retries=10):
    while retries:
        udp_socket = None
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(1)
            #   发送数据（数据，(ip,端口)）
            udp_socket.sendto(packet, (endpoint.ip, endpoint.port))
            ur = udp_socket.recvfrom(1024)
        except Exception as e:
            retries -= 1
        else:
            return ur[0]
        finally:
            if udp_socket:
                udp_socket.close()


def get_request_id() -> int:  # pragma: no cover
    return int(time.mktime(time.localtime()))


def validate_response_id(request_id: int, response_id: int) -> None:
    """
    Compare request and response IDs and raise an appropriate error.

    Raises an appropriate error if the IDs differ. Otherwise returns

    This helper method ensures we're always returning the same exception type
    on invalid response IDs.
    """
    if response_id != request_id:
        raise InvalidResponseId(
            "Invalid response ID {} for request id {}".format(response_id, request_id)
        )


class ClientConfig(object):
    def __init__(self, credentials, context, lcd, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
        self.credentials = credentials
        self.context = context
        self.lcd = lcd
        self.timeout = timeout
        self.retries = retries


class Credentials(object):
    community: str

    def __init__(self, mpm: int):
        self.mpm = mpm

    def __repr__(self) -> str:
        return "<{}.{}>".format(__name__, self.__class__.__name__)


class V1(Credentials):

    def __init__(self, community):
        super().__init__(0)
        self.community = community

    def __eq__(self, other):
        return isinstance(other, V1) and other.community == self.community


class V2C(V1):

    def __init__(self, community: str) -> None:
        super().__init__(community)
        self.mpm = 1


class V3(Credentials):
    def __init__(self, username: str, auth=None, priv=None):
        super().__init__(3)
        self.username = username
        self.auth = auth
        self.priv = priv

    def __eq__(self, other: object) -> bool:
        return (
                isinstance(other, V3)
                and other.username == self.username
                and other.auth == self.auth
                and other.priv == self.priv
        )


class Context(object):
    def __init__(self, engine_id, name):
        self.engine_id = engine_id
        self.name = name


class SNMPv1SecurityModel(object):
    def __init__(self, local_config):
        self.local_config = {}

    def generate_request_message(self, message, security_engine_id, credentials):
        if not isinstance(credentials, V1):
            raise SnmpError(
                "Credentials for the SNMPv1 security model must be "
                "V1 instances!"
            )
        packet = Sequence(
            [Integer(0), OctetString(credentials.community), message]
        )
        return packet


class V2CEncodingResult(object):
    def __init__(self, data, security_model=None):
        self.data = data
        self.security_model = security_model


class SNMPv2cSecurityModel(object):
    """
    Implementation of the security model for community based SNMPv2 messages
    """

    def generate_request_message(self, message, security_engine_id, credentials):
        if not isinstance(credentials, V2C):
            raise SnmpError(
                "Credentials for the SNMPv2c security model must be "
                "V2C instances!"
            )
        packet = Sequence(
            [Integer(1), OctetString(credentials.community), message]
        )
        return packet

    def process_incoming_message(self, message, credentials):
        proto_version, community, pdu = message
        if not isinstance(credentials, V2C):
            raise SnmpError(
                "Credentials for the SNMPv2c security model must be "
                "V2C instances!"
            )
        if proto_version.pythonize() != 1:
            raise SnmpError(
                "Incoming SNMP message is not supported by the SNMPv2c "
                "security model. Most likely the device is not talking "
                "SNMPv2c but rather a different SNMP version."
            )
        if community.pythonize() != credentials.community.encode("ascii"):
            raise SnmpError("Mismatching community in response mesasge!")

        return pdu  # type: ignore


class V1MPM(object):
    def encode(self, request_id, credentials, engine_id, context_name, pdu):
        pass


class V2CMPM(object):

    def __init__(self, transport_handler, lcd):
        self.transport_handler = transport_handler
        self.lcd = lcd
        self.disco = None
        self.security_model = None

    def encode(self, request_id, credentials, engine_id, context_name, pdu):
        security_model_id = 2
        if self.security_model is None:
            self.security_model = SNMPv2cSecurityModel()
        packet = self.security_model.generate_request_message(pdu, b"", credentials)
        f = V2CEncodingResult(packet.to_bytes())
        return f

    def decode(self, whole_msg, credentials):
        """
        Convert an SNMPv2c message into a PDU instance
        """

        security_model_id = 2
        if self.security_model is None:
            self.security_model = SNMPv2cSecurityModel()

        decoded, _ = decode(whole_msg, enforce_type=Sequence)

        msg = self.security_model.process_incoming_message(decoded, credentials)
        return msg


def is_confirmed(pdu: PDU) -> bool:
    """
    Return True if the given PDU instance expects a response.
    """
    # XXX TODO This might be doable cleaner with subclassing in puresnmp.pdu
    return isinstance(pdu, GetRequest)


def localise_key(credentials: V3, engine_id: bytes) -> bytes:
    if credentials.priv is None:
        raise SnmpError(
            "Attempting to derive a localised key from an empty "
            "privacy object!"
        )
    if credentials.auth is None:
        raise SnmpError(
            "Attempting to derive a localised key from an empty " "auth object!"
        )
    if credentials.auth.method == "md5":
        hasher = password_to_key(hashlib.md5, 16)
    elif credentials.auth.method == "sha1":
        hasher = password_to_key(hashlib.sha1, 20)
    else:
        raise SnmpError(
            "Unknown authentication method: %r" % credentials.auth.method
        )
    output = hasher(credentials.priv.key, engine_id)
    return output


class ScopedPDU(object):
    def __init__(self, context_engine_id, context_name, data):
        self.context_engine_id = context_engine_id
        self.context_name = context_name
        self.data = data

    def to_bytes(self):
        return self.as_snmp_type().to_bytes()

    @staticmethod
    def decode(data: bytes, slc=None) -> "ScopedPDU":
        sequence, _ = decode(
            data,
            start_index=get_slice_start(slc),
            enforce_type=Sequence,
            strict=False,
        )
        engine_id = sequence[0]
        cname = sequence[1]
        pdu = sequence[2]
        output = ScopedPDU(
            context_engine_id=engine_id,
            context_name=cname,
            data=pdu,
        )
        return output

    def as_snmp_type(self):
        """
        Convert this message into an x.690 Sequence
        """
        return Sequence(
            [
                self.context_engine_id,
                self.context_name,
                self.data,
            ]
        )


class USMSecurityParameters(object):

    def __init__(self, authoritative_engine_id, authoritative_engine_boots, authoritative_engine_time, user_name,
                 auth_params, priv_params):
        self.authoritative_engine_id: bytes = authoritative_engine_id
        self.authoritative_engine_boots: int = authoritative_engine_boots
        self.authoritative_engine_time: int = authoritative_engine_time
        self.user_name: bytes = user_name
        self.auth_params: bytes = auth_params
        self.priv_params: bytes = priv_params

    @staticmethod
    def decode(data: bytes) -> "USMSecurityParameters":
        seq, _ = decode(data, enforce_type=Sequence)
        return USMSecurityParameters.from_snmp_type(seq)

    @staticmethod
    def from_snmp_type(seq: Sequence) -> "USMSecurityParameters":
        return USMSecurityParameters(
            authoritative_engine_id=seq[0].pythonize(),
            authoritative_engine_boots=seq[1].pythonize(),
            authoritative_engine_time=seq[2].pythonize(),
            user_name=seq[3].pythonize(),
            auth_params=seq[4].pythonize(),
            priv_params=seq[5].pythonize(),
        )

    def to_bytes(self) -> bytes:
        return self.as_snmp_type().to_bytes()

    def as_snmp_type(self) -> Sequence:
        return Sequence(
            [
                OctetString(self.authoritative_engine_id),
                Integer(self.authoritative_engine_boots),
                Integer(self.authoritative_engine_time),
                OctetString(self.user_name),
                OctetString(self.auth_params),
                OctetString(self.priv_params),
            ]
        )


class Message(object):
    def __init__(self, version, header, security_parameters, scoped_pdu):
        #: The IANA version identifier
        self.version = version
        #: Additional information wrapping the old-style PDU
        self.header = header
        #: Additional data needed to authenticate & en/decrypt the message
        self.security_parameters = security_parameters
        #: The "old-style" PDU (either plain or encrypted)
        self.scoped_pdu = scoped_pdu

    def to_bytes(self) -> bytes:
        if isinstance(self.scoped_pdu, ScopedPDU):
            spdu = self.scoped_pdu.as_snmp_type()
        else:
            spdu = self.scoped_pdu

        output = Sequence(
            [
                self.version,
                self.header.as_snmp_type(),
                OctetString(self.security_parameters),
                spdu,
            ]
        )
        return output.to_bytes()

    @classmethod
    def from_sequence(cls, seq: Sequence):
        version = seq[0]
        header = seq[1]
        security_parameters = seq[2].value

        msg_id = header[0]
        msg_max_size = header[1]
        security_level = V3Flags.decode(header[2])
        security_model_id = header[3].pythonize()

        if security_level.priv:
            payload = seq[3]
        else:
            scoped_pdu = seq[3]
            engine_id = scoped_pdu[0]
            context_name = scoped_pdu[1]
            pdu = scoped_pdu[2]
            payload = ScopedPDU(engine_id, context_name, pdu)

        output = cls(
            version,
            HeaderData(
                msg_id.pythonize(),
                msg_max_size.pythonize(),
                security_level,
                security_model_id,
            ),
            security_parameters,
            payload,
        )

        return output

    @staticmethod
    def decode(data: bytes):
        message, _ = decode(data, enforce_type=Sequence)
        cls = (
            EncryptedMessage
            if isinstance(message[3], OctetString)
            else PlainMessage
        )
        return cls.from_sequence(message)  # type: ignore


class PlainMessage(Message):
    pass


def apply_encryption(
        message: PlainMessage,
        credentials: V3,
        security_name: bytes,
        security_engine_id: bytes,
        engine_boots: int,
        engine_time: int,
):
    if credentials.priv is not None and not credentials.priv.method:
        raise UnsupportedSecurityLevel("Encryption method is missing")

    if credentials.priv is None:
        message.security_parameters = USMSecurityParameters(
            security_engine_id,
            engine_boots,
            engine_time,
            security_name,
            b"",
            b"",
        ).to_bytes()
        return message
    _m = credentials.priv.method
    from usr.snmp_priv import AES_PRIV, DES_PRIV
    if _m == AES_PRIV.IDENTIFIER:
        priv_method = AES_PRIV()
    else:
        priv_method = DES_PRIV()
    localised_key = localise_key(credentials, security_engine_id)
    try:
        encrypted, salt = priv_method.encrypt_data(
            localised_key,
            security_engine_id,
            engine_boots,
            engine_time,
            message.scoped_pdu.to_bytes(),
        )
        scoped_pdu = OctetString(encrypted)
    except Exception as exc:
        raise EncryptionError("Unable to encrypt message ({})".format(exc))

    message.scoped_pdu = scoped_pdu
    message.security_parameters = USMSecurityParameters(
        security_engine_id,
        engine_boots,
        engine_time,
        security_name,
        b"",
        salt,
    ).to_bytes()
    return message


class V3Flags(object):

    def __init__(self, auth=False, priv=False, reportable=False):
        self.auth = auth
        self.priv = priv
        self.reportable = reportable

    @staticmethod
    def decode(blob: OctetString) -> "V3Flags":
        flags = int.from_bytes(blob.value, "big")
        reportable = bool(flags & 0b100)
        priv = bool(flags & 0b010)
        auth = bool(flags & 0b001)
        return V3Flags(auth, priv, reportable)

    def to_bytes(self) -> bytes:
        value = 0
        value |= int(self.reportable) << 2
        value |= int(self.priv) << 1
        value |= int(self.auth)
        return bytes([value])


def reset_digest(message: Message) -> Message:
    secparams = USMSecurityParameters.decode(message.security_parameters)
    secparams.auth_params = b"\x00" * 12
    neutral = secparams
    message.security_parameters = neutral.to_bytes()
    output = message
    return output


def apply_authentication(
        unauthed_message,
        credentials: V3,
        security_engine_id: bytes,
):
    if credentials.auth is not None and not credentials.auth.method:
        raise UnsupportedSecurityLevel(
            "Incomplete data for authentication. "
            "Need both an auth-key and an auth-method!"
        )

    if credentials.auth is None:
        return unauthed_message

    from usr.snmp_auth import MD5_AUTH, SHA1_AUTH
    _m = credentials.auth.method
    if _m == MD5_AUTH.IDENTIFIER:
        auth_method = MD5_AUTH()
    else:
        auth_method = SHA1_AUTH()
    try:
        without_digest = reset_digest(unauthed_message)
        auth_result = auth_method.authenticate_outgoing_message(
            credentials.auth.key,
            without_digest.to_bytes(),
            security_engine_id,
        )
        security_params = USMSecurityParameters.decode(unauthed_message.security_parameters)
        security_params.auth_params = auth_result

        authed_message = unauthed_message
        authed_message.security_parameters = security_params.to_bytes()
        return authed_message
    except Exception as exc:
        raise AuthenticationError(
            "Unable to authenticat the message ({})".format(exc)
        )


def verify_authentication(
        message: Message, credentials: V3, security_params: USMSecurityParameters
) -> None:
    if not message.header.flags.auth:
        return

    if not credentials.auth:
        raise UnsupportedSecurityLevel(
            "Message requires authentication but auth-method is missing!"
        )
    from usr.snmp_auth import MD5_AUTH, SHA1_AUTH
    _m = credentials.auth.method
    if _m == MD5_AUTH.IDENTIFIER:
        auth_method = MD5_AUTH()
    else:
        auth_method = SHA1_AUTH()
    without_digest = reset_digest(message)
    is_authentic = auth_method.authenticate_incoming_message(
        credentials.auth.key,
        without_digest.to_bytes(),
        security_params.auth_params,
        security_params.authoritative_engine_id,
    )
    if not is_authentic:
        raise AuthenticationError(
            "Incoming message could not be authenticated!"
        )


class HeaderData(object):

    def __init__(self, message_id, message_max_size, flags, security_model):
        self.message_id: int = message_id
        self.message_max_size: int = message_max_size
        self.flags: V3Flags = flags
        self.security_model: int = security_model

    def as_snmp_type(self) -> Sequence:
        return Sequence(
            [
                Integer(self.message_id),
                Integer(self.message_max_size),
                OctetString(self.flags.to_bytes()),
                Integer(self.security_model),
            ]
        )

    def to_bytes(self) -> bytes:
        return self.as_snmp_type().to_bytes()


def validate_usm_message(message: PlainMessage) -> None:
    """
    If the message contains known error-indicators, raise an appropriate
    exception.

    :raises SnmpError: If an error was found
    """
    pdu = message.scoped_pdu.data.value
    errors = {
        ObjectIdentifier(
            "1.3.6.1.6.3.15.1.1.1.0"
        ): "Unsupported security level",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.2.0"): "Not in time window",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.3.0"): "Unknown user-name",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.4.0"): "Unknown engine-id",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.5.0"): "Wrong message digest",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.6.0"): "Unable to decrypt",
    }
    for varbind in pdu.varbinds:
        if varbind.oid in errors:
            msg = errors[varbind.oid]
            raise SnmpError("Error response from remote device: {}".format(msg))


def decrypt_message(
        message, credentials: V3
) -> PlainMessage:
    """
    Decrypt a message using the given credentials
    """
    if isinstance(message, PlainMessage):
        return message

    if not credentials.priv:
        raise SnmpError("Attempting to decrypt a message without priv object")
    _m = credentials.priv.method
    from usr.snmp_priv import AES_PRIV, DES_PRIV
    if _m == AES_PRIV.IDENTIFIER:
        priv_method = AES_PRIV()
    else:
        priv_method = DES_PRIV()
    key = credentials.priv.key
    if not isinstance(message.scoped_pdu, OctetString):
        raise SnmpError(
            "Unexpectedly received unencrypted PDU with a security level "
            "requesting encryption!"
        )
    security_parameters = USMSecurityParameters.decode(
        message.security_parameters
    )
    localised_key = localise_key(
        credentials, security_parameters.authoritative_engine_id
    )
    try:
        decrypted = priv_method.decrypt_data(
            localised_key,
            security_parameters.authoritative_engine_id,
            security_parameters.authoritative_engine_boots,
            security_parameters.authoritative_engine_time,
            security_parameters.priv_params,
            message.scoped_pdu.value,
        )
        message.scoped_pdu = ScopedPDU.decode(decrypted)
    except Exception as exc:
        raise DecryptionError("Unable to decrypt message ({})".format(exc))
    return message


class UserSecurityModel(object):
    def __init__(self):
        self.local_config = {}

    def set_engine_timing(
            self,
            engine_id: bytes,
            engine_boots: int,
            engine_time: int,
    ) -> None:
        engine_config = self.local_config.setdefault(engine_id, {})
        engine_config["authoritative_engine_boots"] = engine_boots
        engine_config["authoritative_engine_time"] = engine_time

    def generate_request_message(self, message: PlainMessage, security_engine_id: bytes, credentials: Credentials):
        if not isinstance(credentials, V3):
            raise TypeError(
                "Credentials must be a V3 instance for this scurity model!"
            )

        security_name = credentials.username.encode("ascii")
        engine_config = self.local_config[security_engine_id]
        engine_boots = engine_config["authoritative_engine_boots"]
        engine_time = engine_config["authoritative_engine_time"]

        encrypted_message = apply_encryption(
            message,
            credentials,
            security_name,
            security_engine_id,
            engine_boots,
            engine_time,
        )

        authed_message = apply_authentication(
            encrypted_message, credentials, security_engine_id
        )

        return authed_message

    def process_incoming_message(
            self,
            message,
            credentials: Credentials,
    ) -> PlainMessage:

        if not isinstance(credentials, V3):
            raise SnmpError("Supplied credentials is not a V3 instance!")

        security_params = USMSecurityParameters.decode(
            message.security_parameters
        )

        security_name = security_params.user_name
        if security_name != credentials.username.encode("ascii"):
            # See https://tools.ietf.org/html/rfc3414#section-3.1
            raise UnknownUser("Unknown user {}".format(security_name))

        verify_authentication(message, credentials, security_params)
        message = decrypt_message(message, credentials)
        validate_usm_message(message)
        return message

    def send_discovery_message(self, transport_handler):

        request_id = get_request_id()
        security_params = USMSecurityParameters(
            authoritative_engine_id=b"",
            authoritative_engine_boots=0,
            authoritative_engine_time=0,
            user_name=b"",
            auth_params=b"",
            priv_params=b"",
        )
        discovery_message = Message(
            Integer(3),
            HeaderData(
                request_id,
                MESSAGE_MAX_SIZE,
                V3Flags(False, False, True),
                3,
            ),
            security_params.to_bytes(),
            ScopedPDU(
                OctetString(),
                OctetString(),
                GetRequest(PDUContent(request_id, [])),
            ),
        )
        payload = discovery_message.to_bytes()
        raw_response = transport_handler(payload)
        response, _ = decode(raw_response, enforce_type=Sequence)
        if isinstance(response, Null):
            raise SnmpError("Unexpectedly got a NULL object")

        response_msg = PlainMessage.from_sequence(response)

        response_id = response_msg.header.message_id
        validate_response_id(request_id, response_id)

        security = USMSecurityParameters.decode(
            response_msg.security_parameters
        )
        wrapped_vars = response_msg.scoped_pdu.data.value.varbinds
        if not wrapped_vars:
            raise SnmpError("Invalid discovery response (no varbinds returned)")
        unknown_engine_id_var = wrapped_vars[0]
        if not unknown_engine_id_var.value:
            raise SnmpError("Discovery data did not contain valid data")
        unknown_engine_ids = unknown_engine_id_var.value.pythonize()

        out = DiscoData(
            authoritative_engine_id=security.authoritative_engine_id,
            authoritative_engine_boots=security.authoritative_engine_boots,
            authoritative_engine_time=security.authoritative_engine_time,
            unknown_engine_ids=unknown_engine_ids,
        )
        return out


class V3EncodingResult(object):
    def __init__(self, data, security_model=None):
        self.data = data
        self.security_model = security_model


class V3MPM(object):

    def __init__(self, transport_handler, lcd):
        self.transport_handler = transport_handler
        self.lcd = lcd
        self.disco = None
        self.security_model = None

    def decode(
            self,
            whole_msg: bytes,  # as received from the network
            credentials: Credentials,
    ) -> PDU:
        security_model_id = 3
        if self.security_model is None:
            self.security_model = UserSecurityModel()
        message = Message.decode(whole_msg)
        msg = self.security_model.process_incoming_message(message, credentials)
        return msg.scoped_pdu.data

    def encode(
            self,
            request_id: int,
            credentials: Credentials,
            engine_id: bytes,
            context_name: bytes,
            pdu: PDU,
    ) -> V3EncodingResult:

        if not isinstance(credentials, V3):
            raise TypeError("Credentials for SNMPv3 must be V3 instances!")

        security_model_id = 3
        if self.security_model is None:
            self.security_model = UserSecurityModel()

        # We need to determine some values from the remote host for security.
        # These can be retrieved by sending a so called discovery message.
        if not self.disco:
            self.disco = self.security_model.send_discovery_message(
                self.transport_handler
            )
        security_engine_id = self.disco.authoritative_engine_id

        if engine_id == b"":
            engine_id = security_engine_id

        scoped_pdu = ScopedPDU(
            OctetString(engine_id), OctetString(context_name), pdu
        )
        flags = V3Flags(
            auth=credentials.auth is not None,
            priv=credentials.priv is not None,
            reportable=is_confirmed(pdu),
        )
        header = HeaderData(
            request_id,
            MESSAGE_MAX_SIZE,
            flags,
            security_model_id,
        )

        if self.disco is not None:
            self.security_model.set_engine_timing(
                self.disco.authoritative_engine_id,
                self.disco.authoritative_engine_boots,
                self.disco.authoritative_engine_time,
            )

        snmp_version = 3
        msg = PlainMessage(Integer(snmp_version), header, b"", scoped_pdu)
        output = self.security_model.generate_request_message(
            msg,
            security_engine_id,
            credentials,
        )

        outgoing_message = output.to_bytes()
        return V3EncodingResult(outgoing_message, self.security_model)


class PDUContent(object):
    def __init__(self, request_id, varbinds, error_status=0, error_index=0):
        self.request_id = request_id
        self.varbinds = varbinds
        self.error_status = error_status
        self.error_index = error_index


def tablify(
        varbinds,
        num_base_nodes: int = 0,
        base_oid: str = "",
        _rowtype=None):
    if _rowtype is None:
        _rowtype = dict()
    if isinstance(base_oid, str) and base_oid:
        base_oid_parsed = ObjectIdentifier(base_oid)
        # Each table has a sub-index for the table "entry" so the number of
        # base-nodes needs to be incremented by 1
        num_base_nodes = len(base_oid_parsed)

    rows = {}
    for oid, value in varbinds:
        if num_base_nodes:
            tail = oid.nodes[num_base_nodes:]
            col_id_nodes, row_id_nodes = tail[0], tail[1:]
            col_id = str(col_id_nodes)
            row_id = ".".join([str(node) for node in row_id_nodes])
        else:
            col_id = str(oid.nodes[-2])
            row_id = str(oid.nodes[-1])
        tmp: TTableRow = {  # type: ignore
            "0": row_id,
        }
        row = rows.setdefault(row_id, tmp)
        row[str(col_id)] = value
    return list(rows.values())


class Client(object):
    def __init__(self, ip, credentials, port=161, sender=udp_send, context_name=b"", engine_id=b""):
        lcd = dict()
        self.config = ClientConfig(
            credentials=credentials,
            context=Context(engine_id, context_name),
            lcd=lcd,
        )
        self.endpoint = Endpoint(ip, port)

        def handler(data):
            return sender(self.endpoint, data, timeout=self.config.timeout, retries=self.config.retries)

        if credentials.mpm == 1:
            self.mpm = V2CMPM(handler, lcd)
        else:
            self.mpm = V3MPM(handler, lcd)

        self.sender = sender
        self.initialization()

    def initialization(self):
        if not X690Type.INIT:
            X690Type.register(UnknownType)
            X690Type.register(Boolean)
            X690Type.register(Null)
            X690Type.register(OctetString)
            X690Type.register(Sequence)
            X690Type.register(Integer)
            X690Type.register(ObjectIdentifier)
            X690Type.register(ObjectDescriptor)
            X690Type.register(External)
            X690Type.register(Real)
            X690Type.register(Enumerated)
            X690Type.register(EmbeddedPdv)
            X690Type.register(Utf8String)
            X690Type.register(RelativeOid)
            X690Type.register(Set)
            X690Type.register(NumericString)
            X690Type.register(PrintableString)
            X690Type.register(T61String)
            X690Type.register(VideotexString)
            X690Type.register(IA5String)
            X690Type.register(UtcTime)
            X690Type.register(GeneralizedTime)
            X690Type.register(GraphicString)
            X690Type.register(VisibleString)
            X690Type.register(GeneralString)
            X690Type.register(UniversalString)
            X690Type.register(CharacterString)
            X690Type.register(BmpString)
            X690Type.register(EOC)
            X690Type.register(BitString)
            X690Type.register(Counter64)
            X690Type.register(Counter)
            X690Type.register(Gauge)
            X690Type.register(TimeTicks)
            X690Type.register(Opaque)
            X690Type.register(NsapAddress)
            X690Type.register(PDU)
            X690Type.register(NoSuchObject)
            X690Type.register(NoSuchInstance)
            X690Type.register(EndOfMibView)
            X690Type.register(GetRequest)
            X690Type.register(GetResponse)
            X690Type.register(GetNextRequest)
            X690Type.register(SetRequest)
            X690Type.register(BulkGetRequest)
            X690Type.register(InformRequest)
            X690Type.register(Trap)
            X690Type.register(Report)
            X690Type.register(IpAddress)
            X690Type.INIT = True
        if not ErrorResponse.INIT:
            ErrorResponse.register(TooBig)
            ErrorResponse.register(NoSuchOID)
            ErrorResponse.register(BadValue)
            ErrorResponse.register(ReadOnly)
            ErrorResponse.register(GenErr)
            ErrorResponse.register(NoAccess)
            ErrorResponse.register(WrongType)
            ErrorResponse.register(WrongLength)
            ErrorResponse.register(WrongEncoding)
            ErrorResponse.register(WrongValue)
            ErrorResponse.register(NoCreation)
            ErrorResponse.register(InconsistentValue)
            ErrorResponse.register(ResourceUnavailable)
            ErrorResponse.register(CommitFailed)
            ErrorResponse.register(UndoFailed)
            ErrorResponse.register(AuthorizationError)
            ErrorResponse.register(NotWritable)
            ErrorResponse.register(InconsistentName)
            ErrorResponse.INIT = True

    def reload(self):
        X690Type.INIT = False
        ErrorResponse.INIT = False
        self.initialization()

    def _send(self, pdu, request_id):
        ret = self.mpm.encode(request_id, self.credentials, self.context.engine_id, self.context.name, pdu)
        raw_resp = self.sender(self.endpoint, ret.data, timeout=self.config.timeout, retries=self.config.retries)
        resp = self.mpm.decode(raw_resp, self.credentials)
        validate_response_id(request_id, resp.value.request_id)
        return resp

    @property
    def credentials(self) -> Credentials:
        return self.config.credentials

    @property
    def context(self) -> Context:
        return self.config.context

    @property
    def ip(self):
        return self.endpoint.ip

    @property
    def port(self) -> int:
        return self.endpoint.port

    def get(self, oid):
        oid = ObjectIdentifier(oid)
        result = self.multiget([oid])
        return result

    def multiget(self, oids):
        parsed_oids = [VarBind(oid, Null()) for oid in oids]
        request_id = get_request_id()
        pdu = GetRequest(PDUContent(request_id, parsed_oids))
        return self._send(pdu, request_id)

    def getnext(self, oid):
        result = self.multigetnext([oid])
        if isinstance(result[0], (NoSuchObject, NoSuchInstance)):
            raise NoSuchOID(oid)
        return result[0]

    def walk(self, oid, errors=ERRORS_STRICT):
        """
        A convenience method delegating to :py:meth:`~.multiwalk` with
        exactly one OID
        """
        for row in self.multiwalk([oid], errors=errors):
            yield row

    def multiwalk(self, oids, fetcher=None, errors=ERRORS_STRICT):
        if fetcher is None:
            fetcher = self.multigetnext

        print("DEBUG Walking on %d OIDs using" % len(oids))
        varbinds = fetcher(oids)
        grouped_oids = group_varbinds(varbinds, oids)
        unfinished_oids = get_unfinished_walk_oids(grouped_oids)
        yielded = set()
        for varbind in deduped_varbinds(oids, grouped_oids, yielded):
            yield varbind

        # As long as we have unfinished OIDs, we need to continue the walk for
        # those.
        while unfinished_oids:
            next_fetches = [_[1].value.oid for _ in unfinished_oids]
            try:
                varbinds = fetcher(next_fetches)
            except NoSuchOID:
                # Reached end of OID tree, finish iteration
                break
            except FaultySNMPImplementation as exc:
                if errors == ERRORS_WARN:
                    print(
                        "WARNING SNMP walk aborted prematurely due to faulty SNMP "
                        "implementation on device %r! Upon running a "
                        "GetNext on OIDs %r it returned the following "
                        "error: %s" % (
                            self.endpoint,
                            next_fetches,
                            exc,
                        ))
                    break
                raise
            grouped_oids = group_varbinds(
                varbinds, next_fetches, user_roots=oids
            )
            unfinished_oids = get_unfinished_walk_oids(grouped_oids)
            if len(oids) > 1:
                print(
                    "DEBUG, %d of %d OIDs need to be continued" % (
                        len(unfinished_oids),
                        len(oids),
                    ))
            for varbind in deduped_varbinds(oids, grouped_oids, yielded):
                yield varbind

    def multigetnext(self, oids):
        varbinds = [VarBind(oid, Null()) for oid in oids]
        request_id = get_request_id()
        pdu = GetNextRequest(PDUContent(request_id, varbinds))
        response_object = self._send(pdu, request_id)
        if len(response_object.value.varbinds) != len(oids):
            raise SnmpError(
                "Invalid response! Expected exactly %d varbind, "
                "but got %d" % (len(oids), len(response_object.value.varbinds))
            )

        output = []
        for tmp in response_object.value.varbinds:
            if isinstance(tmp.value, EndOfMibView):
                break
            output.append(VarBind(tmp.oid, tmp.value))

        # Verify that the OIDs we retrieved are successors of the requested OIDs
        for requested, retrieved in zip(oids, output):
            if not requested < retrieved.oid:
                raise FaultySNMPImplementation(
                    "The OID %s is not a successor of %s!"
                    % (retrieved.oid, requested)
                )
        return output

    def table(self, oid, _rowtype=None):
        if _rowtype is None:
            _rowtype = dict()
        tmp = []
        varbinds = self.walk(oid)
        for varbind in varbinds:
            tmp.append(varbind)
        as_table = tablify(
            tmp, num_base_nodes=len(oid), _rowtype=_rowtype
        )
        return as_table

    def set(self, oid: ObjectIdentifier, value):
        value_internal = value
        result = self.multiset({oid: value_internal})
        return result[oid]  # type: ignore

    def multiset(self, mappings):
        if any(not isinstance(v, X690Type) for v in mappings.values()):
            raise TypeError(
                "SNMP requires typing information. The value for a "
                '"set" request must be an instance of "Type"!'
            )

        binds = [VarBind(oid, value) for oid, value in mappings.items()]

        pdu = SetRequest(PDUContent(get_request_id(), binds))
        response = self._send(pdu, get_request_id())

        output = {tmp.oid: tmp.value for tmp in response.value.varbinds}
        if len(output) != len(mappings):
            raise SnmpError(
                "Unexpected response. Expected %d varbinds, "
                "but got %d!" % (len(mappings), len(output))
            )
        return output

    def bulkget(self, scalar_oids, repeating_oids, max_list_size=1):

        scalar_oids = scalar_oids or []  # protect against empty values
        repeating_oids = repeating_oids or []  # protect against empty values

        oids = list(scalar_oids) + list(repeating_oids)

        non_repeaters = len(scalar_oids)

        request_id = get_request_id()
        pdu = BulkGetRequest(request_id, non_repeaters, max_list_size, *oids)
        get_response = self._send(pdu, request_id)

        # See RFC=3416 for details of the following calculation
        n = min(non_repeaters, len(oids))
        m = max_list_size
        r = max(len(oids) - n, 0)  # pylint: disable=invalid-name
        expected_max_varbinds = n + (m * r)

        n_retrieved_varbinds = len(get_response.value.varbinds)
        if n_retrieved_varbinds > expected_max_varbinds:
            raise SnmpError(
                "Unexpected response. Expected no more than %d "
                "varbinds, but got %d!"
                % (expected_max_varbinds, n_retrieved_varbinds)
            )

        # cut off the scalar OIDs from the listing(s)
        scalar_tmp = get_response.value.varbinds[0: len(scalar_oids)]
        repeating_tmp = get_response.value.varbinds[len(scalar_oids):]

        # prepare output for scalar OIDs
        scalar_out = {}
        for tmp in scalar_tmp:
            scalar_out[tmp.oid] = tmp.value

        # prepare output for listing
        repeating_out = []
        for tmp in repeating_tmp:
            if isinstance(tmp.value, EndOfMibView):
                break
            repeating_out.append(tmp)

        return BulkResult(scalar_out, repeating_out)

    def _bulkwalk_fetcher(self, bulk_size: int = 10):
        def fetcher(oids):
            result = self.bulkget([], oids, max_list_size=bulk_size)
            return result.listing

        return fetcher

    def bulkwalk(self, oids, bulk_size=10):
        if not isinstance(oids, list):
            raise TypeError("OIDS need to be passed as list!")

        result = self.multiwalk(
            oids,
            fetcher=self._bulkwalk_fetcher(bulk_size),
        )
        for oid, value in result:
            yield VarBind(oid, value)

    def bulktable(self, oid, bulk_size=10, _rowtype=None):
        if _rowtype is None:
            _rowtype = dict()
        tmp = []
        varbinds = self.bulkwalk([oid], bulk_size=bulk_size)
        for varbind in varbinds:
            tmp.append(varbind)
        as_table = tablify(tmp, num_base_nodes=len(oid) + 1, _rowtype=_rowtype)
        return as_table


if __name__ == '__main__':
    cl = Client("192.168.56.10", V2C("public"))
    resp = cl.get("1.3.6.1.2.1.1.1.0")
    for item in resp.value.varbinds:
        print(item.oid, item.value.value)
