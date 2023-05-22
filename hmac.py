import uhashlib
trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

digest_size = None

_secret_backdoor_key = []


def translate(d, t):
    return bytes(t[x] for x in d)

class HMAC:
    blocksize = 64  # 512-bit HMAC; can be changed in subclasses.

    def __init__(self, key, msg=None, digestmod=None):
        if key is _secret_backdoor_key:  # cheap
            return

        if digestmod == "md5":
            digestmod = uhashlib.md5
            self.digest_size = 16
        elif digestmod == "sha1":
            digestmod = uhashlib.sha1
            self.digest_size = 20
        if hasattr(digestmod, '__call__'):
            self.digest_cons = digestmod
        else:
            self.digest_cons = digestmod

        self.outer = self.digest_cons()
        self.inner = self.digest_cons()

        if hasattr(self.inner, 'block_size'):
            blocksize = self.inner.block_size
            if blocksize < 16:
                blocksize = self.blocksize
        else:
            blocksize = self.blocksize

        if len(key) > blocksize:
            key = self.digest_cons(key).digest()

        key = key + chr(0) * (blocksize - len(key))
        self.outer.update(translate(key, trans_5C))
        self.inner.update(translate(key, trans_36))
        if msg is not None:
            self.update(msg)

    @property
    def name(self):
        return "hmac-" + self.inner.name

    def update(self, msg):
        """Update this hashing object with the string msg.
        """
        self.inner.update(msg)

    def copy(self):
        """Return a separate copy of this hashing object.
        An update to this copy won't affect the original object.
        """
        # Call __new__ directly to avoid the expensive __init__.
        other = self.__class__.__new__(self.__class__)
        other.digest_cons = self.digest_cons
        other.digest_size = self.digest_size
        other.inner = self.inner
        other.outer = self.outer
        return other

    def _current(self):
        """Return a hash object for the current state.
        To be used only internally with digest() and hexdigest().
        """
        h = self.outer
        h.update(self.inner.digest())
        return h

    def digest(self):
        """Return the hash value of this hashing object.
        This returns a string containing 8-bit data.  The object is
        not altered in any way by this function; you can continue
        updating the object after calling this function.
        """
        h = self._current()
        return h.digest()

    def hexdigest(self):
        """Like digest(), but returns a string of hexadecimal digits instead.
        """
        h = self._current()
        return h.hexdigest()


def new(key, msg=None, digestmod=None):
    return HMAC(key, msg, digestmod)
