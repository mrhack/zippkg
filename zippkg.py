#!coding=utf8
"""
Read and write ZIP files.
"""
import os
import zlib
import math
import binascii
from StringIO import StringIO

from util.formater import *
from util.crypt import *
from util.compress import *

from struct_def import *


class Params:
    '''
    add dict key to instance's attribute, value to value
    '''

    def __init__(self, _dict):
        for k, v in _dict.iteritems():
            setattr(self, k, v)

    def __getattr__(self, key):
        return None


class BadZipfile(Exception):
    pass


class BadPassword(Exception):
    pass


def checkCRC(crc32, content):
    if crc32 != 0 and crc32 != (zlib.crc32(content) & 0xffffffff):
        return False
    else:
        return True


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

    def __init__(self, _bytes):
        self.bytes = _bytes
        self.stream = StringIO(_bytes)
        self.parsed_extra = {}
        self.all_extra = {}
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


class ZipInfo(object):
    def __init__(self, stream, container, password=None):

        self.is_encrypted = container.general_purpose_bit_flag & 0x1
        self.password = password
        self.container = container
        self.stream = stream
        self._parseExtra()

    def _checkZip64Extra(self, zip64_extra):
        # https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
        # 4.5.3: If one of the size or
        # offset fields in the Local or Central directory
        # record is too small to hold the required data,
        # a Zip64 extended information record is created.
        # The order of the fields in the zip64 extended
        # information record is fixed, but the fields MUST
        # only appear if the corresponding Local or Central
        # directory record field is set to 0xFFFF or 0xFFFFFFFF.
        keys = ['csize', 'unsize', 'relative_offset_local_header']
        checks = [0xFFFF, 0xFFFFFFFF]
        for key in keys:
            for c in checks:
                if not getattr(zip64_extra, key) ^ c:
                    return True
        return False

    def _parseExtra(self):
        container = self.container
        self.extra = ZipExtra(container.extra_field)
        # zip64
        zip64_extra = self.extra.getExtra(ZipExtra.ZIP64)
        if zip64_extra and self._checkZip64Extra(zip64_extra):
            container.csize = zip64_extra.csize
            container.ucsize = zip64_extra.ucsize
            container.relative_offset_local_header = zip64_extra.relative_offset_local_header

        # unicode path extra field
        upef_extra = self.extra.getExtra(ZipExtra.UPEF)
        if container.general_purpose_bit_flag & 0x800:
            # UTF-8 file names extension
            container.filename = container.filename.decode('utf-8')
        elif upef_extra and checkCRC(upef_extra.crc32, container.filename):
            container.filename = upef_extra.unicode_name.decode('utf-8')
        else:
            # Historical ZIP filename encoding
            container.filename = container.filename.decode('cp437')

    def __getattr__(self, key):
        if hasattr(self.container, key):
            return getattr(self.container, key)
        else:
            raise AttributeError("attribute `{}` is not exist".format(key))

    def read(self, password=None):
        stream = self.stream

        stream.seek(self.container.relative_offset_local_header, os.SEEK_SET)
        file_header = struct_local_file_header.parseStream(stream)

        content = self._decompress(self._decrypt(file_header.csize, password))
        if not checkCRC(self.crc32, content):
            raise BadZipfile('crc32 check failed')

        return content

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
                return AESCrypt(password).decrypt(data, aes_extra, password)
            else:
                # The first 12 bytes in the cypher stream is an encryption header
                #  used to strengthen the algorithm. The first 11 bytes are
                #  completely random, while the 12th contains the MSB of the CRC,
                #  or the MSB of the file time depending on the header type
                #  and is used to check the correctness of the password.
                encryption_header = data[:PKWARECrypt.ENCRYPTION_HEADER_LENGTH]
                crypt = PKWARECrypt(password)
                h = crypt.decrypt(encryption_header)
                if self.general_purpose_bit_flag & 0x8:
                    # compare against the file type from extended local headers
                    check_byte = (self.last_mod_dos_datetime[0] >> 8) & 0xff
                else:
                    # compare against the CRC otherwise
                    check_byte = (self.crc32 >> 24) & 0xff
                if ord(h[11]) != check_byte:
                    raise BadPassword("Bad password for file", self.filename)
                return crypt.decrypt(data[PKWARECrypt.ENCRYPTION_HEADER_LENGTH:])
        else:
            return stream.read(csize)

    def _encrypt(self, data):
        pass

    @property
    def compressor(self):
        if self.is_encrypted and self.extra.getExtra(ZipExtra.AES):
            compression_method = self.extra.getExtra(ZipExtra.AES).compression_method
        else:
            compression_method = self.compression_method
        # set compressor
        return Compressor(compression_method)

    def _compress(self, data):
        return self.compressor.compress(data)

    def _decompress(self, data):
        return self.compressor.decompress(data)


class ZipReader(object):

    def __init__(self, file, password=None):
        self.file = file
        self.password = password
        if isinstance(file, basestring):
            self.stream = open(file, 'rb')
            self.filename = file
        else:
            self.stream = file
            self.filename = getattr(file, 'name', None)

        self.stream.seek(0, os.SEEK_END)
        self.size = self.stream.tell()
        self.comment = ''
        self.is_zip64 = False
        self.end_central_dir = None

        self._fileInfos = []
        self._fileInfosDict = {}
        self._parse()

    def _parse(self):
        stream = self.stream

        # Either this is not a ZIP file, or it is a ZIP file with an archive
        # comment.  Search the end of the file for the "end of central directory"
        # record signature. The comment is the last item in the ZIP file and may be
        # up to 64K long.  It is assumed that the "end of central directory" magic
        # number does not appear in the comment.
        maxCommentSize = 1 << 16
        stream.seek(-min(maxCommentSize, self.size), os.SEEK_END)
        footer = stream.read()
        end_central_dir_offset = footer.rfind(Signature.ZIP_RECORD)
        if end_central_dir_offset == -1:
            raise BadZipfile("File is not a Zip archive")

        stream.seek(stream.tell() - len(footer) + end_central_dir_offset)
        end_central_dir = struct_end_central_dir_record.parseStream(stream)
        self.end_central_dir = end_central_dir
        self.is_zip64 = self._checkZip64()
        if self.is_zip64:
            self._parseZip64()
        self.comment = end_central_dir.zipfile_comment

        if end_central_dir.size_central_dir > 0:
            self._parseCentralDirectoryHeader()

    def _parseZip64(self):
        # parse zip64 end of central directory locator
        zip64_locator_size = struct_zip64_central_dir_locator.size()
        self.stream.seek(-self.end_central_dir.size() - zip64_locator_size, os.SEEK_END)
        zip64_locator = struct_zip64_central_dir_locator.parseStream(self.stream)
        if zip64_locator.disk_index_width_zip64_central_dir_record != 0 and zip64_locator.disk_total != 1:
            raise BadZipfile("zipfiles that span multiple disks are not supported")
        # parse zip64 directory record

        self.stream.seek(zip64_locator.offset_zip64_central_dir_record)
        zip64_record = struct_zip64_central_dir_record.parseStream(self.stream)

        self.end_central_dir.signature = zip64_record.signature
        self.end_central_dir.total_entries_central_dir = zip64_record.total_entries_central_dir
        self.end_central_dir.total_entries_central_dir_disk = zip64_record.total_entries_central_dir_disk
        self.end_central_dir.size_central_dir = zip64_record.size_central_dir
        self.end_central_dir.offset_start_central_dir = zip64_record.offset_start_central_dir

    def _checkZip64(self):
        # https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
        # 4.4.1.4: If one of the fields in the end of central directory
        # record is too small to hold required data, the field should be
        # set to -1 (0xFFFF or 0xFFFFFFFF) and the ZIP64 format record
        # should be created.
        keys = ['total_entries_central_dir_disk', 'total_entries_central_dir']
        checks = [0xFFFF, 0xFFFFFFFF]
        for key in keys:
            for c in checks:
                if not getattr(self.end_central_dir, key) ^ c:
                    return True
        return False

    def _parseCentralDirectoryHeader(self):
        stream = self.stream

        index = 0
        offset = self.end_central_dir.offset_start_central_dir
        while index < self.end_central_dir.total_entries_central_dir:
            stream.seek(offset, os.SEEK_SET)
            dir_header = struct_central_dir_header.parseStream(stream)

            zinfo = ZipInfo(stream, dir_header, self.password)
            self._fileInfos.append(zinfo)
            self._fileInfosDict[zinfo.filename] = zinfo

            offset = stream.tell()
            index += 1

    def infolist(self):
        return self._fileInfos

    def namelist(self):
        return [f.filename for f in self._fileInfos]

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if isinstance(self.file, basestring):
            self.stream.close()

    def read(self, item, password=None):
        if not password:
            password = self.password

        if isinstance(item, basestring):
            if item not in self._fileInfosDict:
                raise IOError('file not found', item)
            item = self._fileInfosDict[item]

        return item.read(password)
