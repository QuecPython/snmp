from collections import namedtuple
from random import randint

EncryptionResult = namedtuple("EncryptionResult", ["ciphertext", "salt"])


class AES_PRIV(object):
    IDENTIFIER = "aes"
    IANA_ID = 4

    @staticmethod
    def pad_packet(data: bytes, block_size: int = 8) -> bytes:
        rest = len(data) % block_size
        if rest == 0:
            return data
        numpad = block_size - rest
        return data + numpad * b"\x00"

    @staticmethod
    def reference_saltpot():
        salt = randint(1, 0xffffff - 1)
        while True:
            yield salt
            salt += 1
            if salt == 0xFFFFFFFFFFFFFFFF:
                salt = 0

    @staticmethod
    def get_iv(engine_boots: int, engine_time: int, local_salt: bytes) -> bytes:
        output = (
                engine_boots << (64 + 32)
                | engine_time << 64
                | int.from_bytes(local_salt, "big")
        )
        return output.to_bytes(16, "big")

    def encrypt_data(
            self,
            localised_key: bytes,
            engine_id: bytes,
            engine_boots: int,
            engine_time: int,
            data: bytes,
    ):
        salt = next(AES_SALTPOT).to_bytes(8, "big")
        iv = self.get_iv(engine_boots, engine_time, salt)
        aes_key = localised_key[:16]
        padded = self.pad_packet(data, 16)
        # TODO 等待AES 算法
        # cipher = Ciphr(algorithms.AES(aes_key), modes.CFB(iv))
        # encryptor = cipher.encryptor()
        # output = encryptor.update(padded) + encryptor.finalize()
        # return EncryptionResult(output, salt)
        return None

    def decrypt_data(
            self,
            localised_key: bytes,
            engine_id: bytes,
            engine_boots: int,
            engine_time: int,
            salt: bytes,
            data: bytes,
    ):
        """
        See https://tools.ietf.org/html/rfc3826#section-3.1.4
        """
        iv = self.get_iv(engine_boots, engine_time, salt)
        aes_key = localised_key[:16]
        padded = self.pad_packet(data, 16)
        # cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        # decryptor = cipher.decryptor()
        # output = decryptor.update(padded) + decryptor.finalize()
        # return output
        return None


AES_SALTPOT = AES_PRIV.reference_saltpot()


class DES_PRIV(object):
    IDENTIFIER = "des"
    IANA_ID = 2

    @staticmethod
    def pad_packet(data: bytes, block_size: int = 8) -> bytes:
        rest = len(data) % block_size
        if rest == 0:
            return data
        numpad = block_size - rest
        return data + numpad * b"\x00"

    @staticmethod
    def reference_saltpot():
        """
        Creates a new source for salt numbers.

        Following :rfc:`3414` this starts at a random number and increases on
        each subsequent retrieval.
        """
        salt = randint(1, 0xFFFFFF - 1)
        while True:
            yield salt
            salt += 1
            if salt == 0xFFFFFFFF:
                salt = 0

    def encrypt_data(
            self,
            localised_key: bytes,
            engine_id: bytes,
            engine_boots: int,
            engine_time: int,
            data: bytes,
    ):
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """

        des_key = localised_key[:8]
        pre_iv = localised_key[8:]

        local_salt = next(DES_SALTPOT)
        salt = (engine_boots & 0xFF).to_bytes(4, "big") + (local_salt & 0xFF).to_bytes(
            4, "big"
        )
        init_vector = bytes(a ^ b for a, b in zip(salt, pre_iv))
        local_salt = next(DES_SALTPOT)

        padded = self.pad_packet(data)
        # cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(init_vector))
        # encryptor = cipher.encryptor()
        # encrypted = encryptor.update(padded) + encryptor.finalize()
        # return EncryptionResult(encrypted, salt)
        return None

    def decrypt_data(
            self,
            localised_key: bytes,
            engine_id: bytes,
            engine_boots: int,
            engine_time: int,
            salt: bytes,
            data: bytes,
    ):
        des_key = localised_key[:8]
        pre_iv = localised_key[8:]
        init_vector = bytes(a ^ b for a, b in zip(salt, pre_iv))
        # cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(init_vector))
        # decryptor = cipher.decryptor()
        # decrypted = decryptor.update(data) + decryptor.finalize()
        # return decrypted
        return None


DES_SALTPOT = DES_PRIV.reference_saltpot()
