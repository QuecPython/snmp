from ucollections import namedtuple

MAX_VARBINDS = 2147483647
ERRORS_STRICT = "strict"
ERRORS_WARN = "warn"
DEFAULT_TIMEOUT = 6
DEFAULT_RETRIES = 10
DEFAULT_LISTEN_ADDRESS = "0.0.0.0"


class SnmpError(Exception):
    ...


class X690Error(Exception):
    ...


class UnexpectedType(X690Error):
    ...


class InvalidResponseId(SnmpError):
    ...


class IncompleteDecoding(X690Error):
    ...

    def __init__(self, message: str, remainder: bytes) -> None:
        super().__init__(message)
        self.remainder = remainder


class ErrorResponse(SnmpError):
    ...
    INIT = False
    DEFAULT_MESSAGE: str = "unknown error"
    IDENTIFIER: int = 0
    error_status: int
    offending_oid: None
    register_map = dict()

    @staticmethod
    def register(cls):
        ErrorResponse.register_map[cls.IDENTIFIER] = cls

    @staticmethod
    def construct(error_status: int, offending_oid, message: str = ""):
        classes = ErrorResponse.register_map
        if error_status in classes:
            cls = classes[error_status]
            return cls(offending_oid, message)
        return ErrorResponse(offending_oid, message, error_status=error_status)

    def __init__(
            self,
            offending_oid,
            message: str = "",
            error_status: int = 0,
    ) -> None:
        error_status = error_status or self.IDENTIFIER
        super().__init__(
            "%s (status-code: %r) on OID %s"
            % (
                message or self.DEFAULT_MESSAGE,
                error_status,
                offending_oid or "unknown",
            )
        )
        self.error_status = error_status
        self.offending_oid = offending_oid


class TooBig(ErrorResponse):
    ...

    DEFAULT_MESSAGE = "SNMP response was too big!"
    IDENTIFIER = 1


class NoSuchOID(ErrorResponse):
    ...

    DEFAULT_MESSAGE = "No such name/oid"
    IDENTIFIER = 2


class BadValue(ErrorResponse):
    ...

    DEFAULT_MESSAGE = "Bad value"
    IDENTIFIER = 3


class ReadOnly(ErrorResponse):
    ...

    DEFAULT_MESSAGE = "Value is read-only!"
    IDENTIFIER = 4


class GenErr(ErrorResponse):
    ...

    DEFAULT_MESSAGE = "General Error (genErr)"
    IDENTIFIER = 5


class NoAccess(ErrorResponse):
    ...

    DEFAULT_MESSAGE = "No Access!"
    IDENTIFIER = 6


class WrongType(ErrorResponse):
    IDENTIFIER = 7


class WrongLength(ErrorResponse):
    IDENTIFIER = 8


class WrongEncoding(ErrorResponse):
    IDENTIFIER = 9


class WrongValue(ErrorResponse):
    IDENTIFIER = 10


class NoCreation(ErrorResponse):
    IDENTIFIER = 11


class InconsistentValue(ErrorResponse):
    IDENTIFIER = 12


class ResourceUnavailable(ErrorResponse):
    IDENTIFIER = 13


class CommitFailed(ErrorResponse):
    IDENTIFIER = 14


class UndoFailed(ErrorResponse):
    IDENTIFIER = 15


class AuthorizationError(ErrorResponse):
    IDENTIFIER = 16


class NotWritable(ErrorResponse):
    IDENTIFIER = 17


class InconsistentName(ErrorResponse):
    IDENTIFIER = 18


class EmptyMessage(SnmpError):
    ...


class TooManyVarbinds(SnmpError):
    ...

    def __init__(self, num_oids):
        # type: (int) -> None
        super().__init__(
            "Too many VarBinds (%d) in one request!"
            " RFC3416 limits requests to %d!" % (num_oids, MAX_VARBINDS)
        )
        self.num_oids = num_oids


class FaultySNMPImplementation(SnmpError):
    ...


class USMError(SnmpError):
    """
    Generic exception for errors cased by the USM module
    """


class UnsupportedSecurityLevel(USMError):
    """
    This error is raised when the data included in the credentials is invalid
    or incomplete.
    """


class EncryptionError(USMError):
    """
    This error is raised whenever something goes wrong during encryption
    """


class DecryptionError(USMError):
    """
    This error is raised whenever something goes wrong during decryption
    """


class AuthenticationError(USMError):
    """
    This error is raised whenever something goes wrong during authentication
    """


class UnknownUser(USMError):
    """
    This error is raised when a message is processed that is not consistent
    with the user-name passed in the credentials.
    """


class TypeClass(object):
    UNIVERSAL = "universal"
    APPLICATION = "application"
    CONTEXT = "context"
    PRIVATE = "private"


class TypeNature(object):
    PRIMITIVE = "primitive"
    CONSTRUCTED = "constructed"


class PDUContent:
    def __init__(self, request_id, varbinds, error_status=0, error_index=0):
        self.request_id = request_id
        self.varbinds = varbinds
        self.error_status = error_status
        self.error_index = error_index


MESSAGE_MAX_SIZE = 65537
BulkResult = namedtuple("BulkResult", ["scalars", "listing"])
WalkRow = namedtuple("WalkRow", ["value", "unfinished"])
Endpoint = namedtuple("Endpoint", ["ip", "port"])
VarBind = namedtuple("VarBind", ["oid", "value"])
EncryptedMessage = namedtuple("EncryptedMessage", ["version", "header", "security_parameters", "scoped_pdu"])
DiscoData = namedtuple("DiscoData",
                       ["authoritative_engine_id", "authoritative_engine_boots", "authoritative_engine_time",
                        "unknown_engine_ids"])
Auth = namedtuple("Auth", ["key", "method"])
Priv = namedtuple("Priv", ["key", "method"])
