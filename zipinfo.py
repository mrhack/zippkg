import os
import zlib
import time
from StringIO import StringIO

from util import DictObject, BadZipfile, expect
from util import crypt
from struct_def import *
from util.compress import Compressor
from zipextra import ZipExtra

ZIP64_FILESIZE_LIMIT = (1 << 31) - 1


def checkCRC(crc32, content):
    if crc32 != 0 and crc32 != (zlib.crc32(content) & 0xffffffff):
        return False
    else:
        return True


class ZipInfo(object):
    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE = 4096
    KWS_DEFAULT = dict(
        password=None,
        comment='',
        cryption=None,
        compression_method=Compressor.ZIP_DEFLATED
    )
    KWS_EXPECT = expect.ExpectDict({
        'password': expect.ExpectStr(noneable=True),
        'cryption': expect.ExpectStr(enum=crypt.Crypt.types, noneable=True),
        'compression_method': expect.ExpectInt(),
        'comment': expect.ExpectStr(noneable=True),
    }, strict=True)

    def __init__(self, stream=None, **kws):
        '''
        expect:
            password=None,
            comment='',
            cryption=None,
            compression_method=Compressor.AES_ENCRYPTED,
        '''
        self.stream = stream
        self.is_encrypted = False
        self.extra = None

        default = self.KWS_DEFAULT.copy()
        default.update(kws)
        self.KWS_EXPECT.validate(default)
        for k, v in default.iteritems():
            setattr(self, k, v)

    def readHeader(self):
        self.dir_header = struct_central_dir_header.parseStream(self.stream)
        self.is_encrypted = self.dir_header.general_purpose_bit_flag & 0x1
        self._parseExtra()

        self.compression_method = self.dir_header.compression_method
        self.is_zip64 = self.extra.getExtra(ZipExtra.ZIP64) is not None
        self.comment = self.dir_header.file_comment

        if self.is_encrypted:
            aes_extra = self.extra.getExtra(ZipExtra.AES)
            if aes_extra:
                self.cryption = aes_extra.encrypt_strength
                self.compression_method = aes_extra.compression_method
            else:
                self.cryption = crypt.CryptTypes.ZIP

    def _parseExtra(self):
        dir_header = self.dir_header

        self.extra = ZipExtra(dir_header.extra_field)
        # zip64
        zip64_extra = self.extra.getExtra(ZipExtra.ZIP64)
        if zip64_extra:
            idx = 0
            # ZIP64 extension (large files and/or large archives)
            counts = unpack_zip64_data(zip64_extra.data)
            if dir_header.ucsize == 0xFFFFFFFFL:
                dir_header.ucsize = counts[idx]
                idx += 1

            if dir_header.csize == 0xFFFFFFFFL:
                dir_header.csize = counts[idx]
                idx += 1

            if dir_header.relative_offset_file_header == 0xFFFFFFFFL:
                dir_header.relative_offset_file_header = counts[idx]
                idx += 1
        # unicode path extra field
        upef_extra = self.extra.getExtra(ZipExtra.UPEF)
        if dir_header.general_purpose_bit_flag & 0x800:
            # UTF-8 file names extension
            dir_header.filename = dir_header.filename.decode('utf-8')
        elif upef_extra and checkCRC(upef_extra.crc32, dir_header.filename):
            dir_header.filename = upef_extra.unicode_name.decode('utf-8')
        else:
            # Historical ZIP filename encoding
            dir_header.filename = dir_header.filename.decode('cp437')

    def __getattr__(self, key):
        if hasattr(self.dir_header, key):
            return getattr(self.dir_header, key)
        else:
            raise AttributeError("attribute `{}` is not exist".format(key))

    def write(self, filename, content='', isdir=False, date_time=(1980, 1, 1, 0, 0, 0)):
        self.is_encrypted = True if self.password else False
        # extra AES
        is_aes_cryption = self.password and self.cryption and self.cryption.startswith('AES')

        # set dir_header
        # ===============================================================
        dosdate = (date_time[0] - 1980) << 9 | date_time[1] << 5 | date_time[2]
        dostime = date_time[3] << 11 | date_time[4] << 5 | (date_time[5] // 2)
        # create file header
        flags = 0x800  # unicode file

        if self.password:
            flags = flags | 0x1
        if type(filename) == unicode:
            filename = filename.encode('utf8')
        if type(content) == unicode:
            content = content.encode('utf8')

        packVals = DictObject({})
        packVals.last_mod_dos_datetime = (dostime, dosdate)
        packVals.general_purpose_bit_flag = flags
        packVals.filename_length = len(filename)
        packVals.filename = filename
        packVals.file_comment = self.comment

        packVals.compression_method = Compressor.AES_ENCRYPTED if is_aes_cryption else self.compression_method
        packVals.file_comment_length = len(self.comment)
        # packVals.external_file_attributes = (st[0] & 0xFFFF) << 16L      # Unix attributes
        packVals.internal_file_attributes = 0
        compressed_data = ''

        if isdir:
            packVals.crc32 = 0
            packVals.external_file_attributes |= 0x10
        else:
            packVals.crc32 = zlib.crc32(content) & 0xffffffff
            # compress
            compressed_data = self._compress(content)

            # encrypt
            if self.password:
                compressed_data = self._encrypt(compressed_data, crc32=packVals.crc32)

            packVals.ucsize = len(content)
            packVals.csize = len(compressed_data)

        packVals.relative_offset_file_header = self.stream.tell()

        # add zip64 fields
        zip64_fields = []
        for key in ['ucsize', 'csize', 'relative_offset_file_header']:
            if getattr(packVals, key) > ZIP64_FILESIZE_LIMIT:
                zip64_fields.append(getattr(packVals, key))
                setattr(packVals, key, 0xFFFFFFFF)
        self.is_zip64 = bool(zip64_fields)
        # set self extras
        # ===============================================================
        extras = []
        if is_aes_cryption:
            extras.append(struct_extra_aes(
                data_length=7,
                vendor_version='AE_1',
                encrypt_strength=self.cryption,
                compression_method=self.compression_method,
            ))

        # extra ZIP64
        if self.is_zip64:
            extras.append(struct_extra_zip64(
                data_length=len(zip64_fields) * 8,
                data=pack_zip64_data(zip64_fields)
            ))

        self.extra = ZipExtra(reduce(lambda x, y: x+y, [_e.pack() for _e in extras], ''))

        extra_field = self.extra.pack()
        self.dir_header = struct_central_dir_header(
            version_made_by=(20, 3),
            version_needed_to_extract=(20, 0),
            extra_field_length=len(extra_field),
            extra_field=extra_field,
            **packVals.__dict__
        )

        file_header = struct_local_file_header(
            version_needed_to_extract=self.dir_header.version_needed_to_extract,
            general_purpose_bit_flag=self.dir_header.general_purpose_bit_flag,
            compression_method=self.dir_header.compression_method,
            last_mod_dos_datetime=self.dir_header.last_mod_dos_datetime,
            crc32=self.dir_header.crc32,
            csize=self.dir_header.csize,
            ucsize=self.dir_header.ucsize,
            filename_length=self.dir_header.filename_length,
            extra_field_length=self.dir_header.extra_field_length,
            filename=self.dir_header.filename,
            extra_field=self.dir_header.extra_field,
        )
        # write file header
        self.stream.write(file_header.pack())
        # write file data
        self.stream.write(compressed_data)

    def read(self, size=None, password=None):
        stream = self.stream
        stream.seek(self.dir_header.relative_offset_file_header, os.SEEK_SET)
        file_header = struct_local_file_header.parseStream(stream)
        csize = self.dir_header.csize or file_header.csize
        if size is not None:
            size = max(size, self.MIN_READ_SIZE)

        if size is None or size > csize:
            content = self._decompress(self._decrypt(csize, password))
            if not checkCRC(self.crc32, content):
                raise BadZipfile('crc32 check failed')
            return content
        # TODO... read large file as stream

    def _decrypt(self, csize, password=None):
        if password == None:
            password = self.password

        stream = self.stream

        if self.is_encrypted:
            if not password:
                raise RuntimeError("password required for extraction", self.filename)

            aes_extra = self.extra.getExtra(ZipExtra.AES)
            data = stream.read(csize)
            if aes_extra:
                return crypt.AESCrypt(password).decrypt(data, aes_extra.encrypt_strength)
            else:
                # The first 12 bytes in the cypher stream is an encryption header
                #  used to strengthen the algorithm. The first 11 bytes are
                #  completely random, while the 12th contains the MSB of the CRC,
                #  or the MSB of the file time depending on the header type
                #  and is used to check the correctness of the password.
                encryption_header = data[:crypt.PKWARECrypt.ENCRYPTION_HEADER_LENGTH]
                _crypt = crypt.PKWARECrypt(password)
                h = _crypt.decrypt(encryption_header)
                if self.general_purpose_bit_flag & 0x8:
                    # compare against the file type from extended local headers
                    check_byte = (self.last_mod_dos_datetime[0] >> 8) & 0xff
                else:
                    # compare against the CRC otherwise
                    check_byte = (self.crc32 >> 24) & 0xff
                if ord(h[-1]) != check_byte:
                    raise crypt.BadPassword("Bad password for file", self.filename)
                return _crypt.decrypt(data[crypt.PKWARECrypt.ENCRYPTION_HEADER_LENGTH:])
        else:
            return stream.read(csize)

    def _encrypt(self, data, password=None, crc32=None):
        if password == None:
            password = self.password

        if password:
            if self.cryption and self.cryption.startswith('AES'):
                return crypt.AESCrypt(password).encrypt(data, self.cryption)
            else:
                # normal zip cryption
                _crypt = crypt.PKWARECrypt(password)
                encryption_header = crypt.random_salt(crypt.PKWARECrypt.ENCRYPTION_HEADER_LENGTH - 1)
                encryption_header += chr((crc32 >> 24) & 0xff)
                encryption_header = _crypt.encrypt(encryption_header)
                return encryption_header + _crypt.encrypt(data)
        else:
            return data

    @property
    def compressor(self):
        return Compressor(self.compression_method)

    def _compress(self, data):
        return self.compressor.compress(data)

    def _decompress(self, data):
        return self.compressor.decompress(data)


class ZipExtra:

    AES = Signature.EXTRA_AES
    UPEF = Signature.EXTRA_UPEF  # Unicode Path Extra Field
    ZIP64 = Signature.EXTRA_ZIP64

    @property
    def structs(self):
        return {
            self.AES: struct_extra_aes,
            self.UPEF: struct_extra_upef,
            self.ZIP64: struct_extra_zip64,
        }

    def __init__(self, bytes):
        self.parsed_extra = {}
        self.all_extra = {}

        self.bytes = bytes
        self.stream = StringIO(bytes)
        self.parse()

    def parse(self):
        length = len(self.bytes)
        last_tell = self.stream.tell()
        while last_tell < length:
            extra = struct_extra_header.parseStream(self.stream)
            self.all_extra[extra.signature] = extra
            struct_detail = self.structs.get(extra.signature)
            if struct_detail:
                self.stream.seek(last_tell)
                self.parsed_extra[extra.signature] = struct_detail.parseStream(self.stream)
            else:
                self.stream.seek(last_tell + extra.size() + extra.data_length)
            last_tell = self.stream.tell()

    def getExtra(self, signature):
        return self.parsed_extra.get(signature)

    def pack(self):
        content = ''
        for _, extra in self.parsed_extra.iteritems():
            content += extra.pack()
        return content

    def __repr__(self):
        out = ['ZipExtra:']
        for _, extra in self.parsed_extra.iteritems():
            lines = extra.__repr__().split('\n')
            out += [' ' * 4 + line for line in lines]

        return '\n'.join(out)
