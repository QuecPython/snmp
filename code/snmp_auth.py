import uhashlib as hashlib
from usr import hmac
from usr.snmp_utils import *


class TOutgoing(object):

    def __call__(self, auth_key: bytes, data: bytes, engine_id: bytes) -> bytes:
        # pylint: disable=unused-argument, missing-docstring
        ...


class TIncoming(object):
    """
    Protocol for callables that authenticate incoming SNMP messages
    """

    # pylint: disable=too-few-public-methods

    def __call__(
            self,
            auth_key: bytes,
            data: bytes,
            received_digest: bytes,
            engine_id: bytes,
    ) -> bool:
        # pylint: disable=unused-argument, missing-docstring
        ...


def for_outgoing(hasher, hmac_method: str):
    def authenticate_outgoing_message(
            auth_key: bytes, data: bytes, engine_id: bytes, *args
    ) -> bytes:
        digest = get_message_digest(
            hasher,
            hmac_method,
            auth_key,
            data,
            engine_id,
        )
        return digest

    return authenticate_outgoing_message


def for_incoming(hasher, hmac_method: str):
    def is_authentic(
            auth_key: bytes, data: bytes, received_digest: bytes, engine_id: bytes
    ) -> bool:
        expected_digest = get_message_digest(
            hasher, hmac_method, auth_key, data, engine_id
        )
        return received_digest == expected_digest

    return is_authentic


def get_message_digest(
        hasher,
        method: str,
        auth_key: bytes,
        encoded_message: bytes,
        engine_id: bytes,
):
    auth_key = hasher(auth_key, engine_id)
    mac = hmac.new(auth_key, msg=encoded_message, digestmod=method)
    return mac.digest()[:12]


class MD5_AUTH(object):
    IDENTIFIER = "md5"
    IANA_ID = 2

    @property
    def hasher(self):
        return password_to_key(hashlib.md5, 16)

    def authenticate_outgoing_message(self, auth_key, data, engine_id):
        return for_outgoing(self.hasher, "md5")(auth_key, data, engine_id)

    def authenticate_incoming_message(self, auth_key: bytes, data: bytes, received_digest: bytes, engine_id: bytes):
        return for_incoming(self.hasher, "md5")(auth_key, data, received_digest, engine_id)


class SHA1_AUTH(object):
    IDENTIFIER = "sha1"
    IANA_ID = 3

    @property
    def hasher(self):
        return password_to_key(hashlib.sha1, 20)

    def authenticate_outgoing_message(self, auth_key, data, engine_id):
        return for_outgoing(self.hasher, "sha1")(auth_key, data, engine_id)

    def authenticate_incoming_message(self, auth_key: bytes, data: bytes, received_digest: bytes, engine_id: bytes):
        return for_incoming(self.hasher, "sha1")(auth_key, data, received_digest, engine_id)
