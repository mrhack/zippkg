
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2


class CryptError(Exception):
    pass


class BadPassword(Exception):
    pass


class Crypt(object):
    def __init__(self, password):
        self.password = password

    def encrypt(self, contents):
        raise NotImplementedError()

    def decrypt(self, contents):
        raise NotImplementedError()


class AESCrypt(Crypt):
    encryption_params = {  # [ salt len, key len ], WinZip v21 can create aes128 (1) and 256 (3) ...
        "AES_128": [8, 16],
        "AES_192": [12, 24],
        "AES_256": [16, 32]
    }

    PASSWD_VERIF_LEN = 2
    AUTH_CODE_LEN = 10
    PBKDF2_ITER = 1000
    NUM_COUNTER_BITS = 128

    def __init__(self, password):
        super(AESCrypt, self).__init__(password)

    def encrypt(self, contents, **kws):
        pass

    def decrypt(self, contents, extra, password=None):
        password = password if password else self.password

        encrypt_strength = extra.encrypt_strength

        salt_len, key_len = self.encryption_params[encrypt_strength]
        salt = contents[:salt_len]
        password_verification_value = contents[salt_len:salt_len+self.PASSWD_VERIF_LEN]

        tell = salt_len + self.PASSWD_VERIF_LEN
        compressed_file_size = len(contents) - (tell + self.AUTH_CODE_LEN)
        encrypted_data = contents[tell:tell+compressed_file_size]
        authentication_code = contents[tell+compressed_file_size:]

        # If prf is not specified, PBKDF2 uses HMAC-SHA1
        keys = PBKDF2(password, salt, dkLen=key_len * 2 + self.PASSWD_VERIF_LEN, count=self.PBKDF2_ITER)
        if keys[-2:] != password_verification_value:
            raise BadPassword("Bad password")

        aes_key, hmac_key = keys[:key_len], keys[key_len:key_len + key_len]
        myhmac = HMAC.new(hmac_key, encrypted_data, SHA).digest()
        if myhmac[:10] != authentication_code:
            raise CryptError("Bad auth code")

        ctr = Counter.new(nbits=self.NUM_COUNTER_BITS, initial_value=1, little_endian=True)
        compressed_data = AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(encrypted_data)

        return compressed_data


class PKWARECrypt(Crypt):
    ENCRYPTION_HEADER_LENGTH = 12
    """Class to handle decryption of files stored within a ZIP archive.
    ZIP supports a password-based form of encryption. Even though known
    plaintext attacks have been found against it, it is still useful
    to be able to get data out of such a file.
    Usage:
        zd = _ZipDecrypter(mypwd)
        plain_char = zd(cypher_char)
        plain_text = map(zd, cypher_text)
    """

    def _generateCRCTable():
        """Generate a CRC-32 table.
        ZIP encryption uses the CRC32 one-byte primitive for scrambling some
        internal keys. We noticed that a direct implementation is faster than
        relying on binascii.crc32().
        """
        poly = 0xedb88320
        table = [0] * 256
        for i in range(256):
            crc = i
            for j in range(8):
                if crc & 1:
                    crc = ((crc >> 1) & 0x7FFFFFFF) ^ poly
                else:
                    crc = ((crc >> 1) & 0x7FFFFFFF)
            table[i] = crc
        return table
    crctable = _generateCRCTable()

    def _crc32(self, ch, crc):
        """Compute the CRC32 primitive on one byte."""
        return ((crc >> 8) & 0xffffff) ^ self.crctable[(crc ^ ord(ch)) & 0xff]

    def __init__(self, password):
        super(PKWARECrypt, self).__init__(password)

        self.key0 = 305419896
        self.key1 = 591751049
        self.key2 = 878082192
        for p in password:
            self._updateKeys(p)

    def _updateKeys(self, c):
        self.key0 = self._crc32(c, self.key0)
        self.key1 = (self.key1 + (self.key0 & 255)) & 4294967295
        self.key1 = (self.key1 * 134775813 + 1) & 4294967295
        self.key2 = self._crc32(chr((self.key1 >> 24) & 255), self.key2)

    def encrypt(self, contents):
        pass

    def decrypt(self, contents):
        data = []
        for c in contents:
            c = ord(c)
            k = self.key2 | 2
            c = c ^ (((k * (k ^ 1)) >> 8) & 255)
            c = chr(c)
            self._updateKeys(c)
            data.append(c)

        return "".join(data)
