#!coding=utf8
"""
Read and write ZIP files.
"""
import os
import zlib
import stat
import time
import math
import binascii
import struct
from StringIO import StringIO

from util import DictObject
from util.formater import *
from util.crypt import *
from util.compress import *
from struct_def import *

ZIP64_FILESIZE_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1

# Zip64 extra field header id
# ------------------------------------
# 0x0001        ZIP64 extended information extra field
# 0x0007        AV Info
# 0x0009        OS/2 extended attributes      (also Info-ZIP)
# 0x000a        NTFS (Win9x/WinNT FileTimes)
# 0x000c        OpenVMS                       (also Info-ZIP)
# 0x000d        Unix
# 0x000f        Patch Descriptor
# 0x0014        PKCS#7 Store for X.509 Certificates
# 0x0015        X.509 Certificate ID and Signature for
#             individual file
# 0x0016        X.509 Certificate ID for Central Directory

# The Header ID mappings defined by Info-ZIP and third parties are:

# 0x0065        IBM S/390 attributes - uncompressed
# 0x0066        IBM S/390 attributes - compressed
# 0x07c8        Info-ZIP Macintosh (old, J. Lee)
# 0x2605        ZipIt Macintosh (first version)
# 0x2705        ZipIt Macintosh v 1.3.5 and newer (w/o full filename)
# 0x334d        Info-ZIP Macintosh (new, D. Haase's 'Mac3' field )
# 0x4154        Tandem NSK
# 0x4341        Acorn/SparkFS (David Pilling)
# 0x4453        Windows NT security descriptor (binary ACL)
# 0x4704        VM/CMS
# 0x470f        MVS
# 0x4854        Theos, old inofficial port
# 0x4b46        FWKCS MD5 (see below)
# 0x4c41        OS/2 access control list (text ACL)
# 0x4d49        Info-ZIP OpenVMS (obsolete)
# 0x4d63        Macintosh SmartZIP, by Macro Bambini
# 0x4f4c        Xceed original location extra field
# 0x5356        AOS/VS (binary ACL)
# 0x5455        extended timestamp
# 0x5855        Info-ZIP Unix (original; also OS/2, NT, etc.)
# 0x554e        Xceed unicode extra field
# 0x6542        BeOS (BeBox, PowerMac, etc.)
# 0x6854        Theos
# 0x756e        ASi Unix
# 0x7855        Info-ZIP Unix (new)
# 0xfb4a        SMS/QDOS


class BadZipfile(Exception):
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
            self.ZIP64: parse_struct_extra_zip64,
        }

    def __init__(self, bytes=None, extras=None):
        self.parsed_extra = {}
        self.all_extra = {}

        if bytes:
            self.bytes = bytes
            self.stream = StringIO(bytes)
            self.parse()

        if extras:
            for extra in extras:
                self.parsed_extra[extra.signature] = extra
                self.all_extra[extra.signature] = extra

    def parse(self):
        length = len(self.bytes)
        last_tell = self.stream.tell()
        while last_tell < length:
            extra = struct_extra_header.parseStream(self.stream)
            self.all_extra[extra.signature] = extra
            struct_detail = self.structs.get(extra.signature)
            if struct_detail:
                if extra.signature == Signature.EXTRA_ZIP64:
                    self.parsed_extra[extra.signature] = struct_detail(self.stream.read(extra.data_length), extra)
                else:
                    self.stream.seek(last_tell)
                    self.parsed_extra[extra.signature] = struct_detail.parseStream(self.stream)
            else:
                self.stream.seek(last_tell + extra.size() + extra.data_length)
            last_tell = self.stream.tell()

    def getExtra(self, signature):
        return self.parsed_extra.get(signature)

    def pack(self):
        pass

    def __repr__(self):
        out = ['ZipExtra:']
        for _, extra in self.parsed_extra.iteritems():
            lines = extra.__repr__().split('\n')
            out += [' ' * 4 + line for line in lines]

        return '\n'.join(out)


class ZipInfo(object):
    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE = 4096

    def __init__(self, stream=None, dir_header=None, password=None):
        self.password = password
        self.dir_header = dir_header
        self.stream = stream
        self.is_encrypted = False

        self.extra = None
        if self.dir_header:
            self.is_encrypted = dir_header.general_purpose_bit_flag & 0x1
            self._parseExtra()

    def _parseExtra(self):
        dir_header = self.dir_header
        self.extra = ZipExtra(dir_header.extra_field)
        # zip64
        zip64_extra = self.extra.getExtra(ZipExtra.ZIP64)
        if zip64_extra:
            idx = 0
            # ZIP64 extension (large files and/or large archives)
            if dir_header.ucsize in (0xffffffffffffffffL, 0xffffffffL):
                dir_header.ucsize = zip64_extra.counts[idx]
                idx += 1

            if dir_header.csize == 0xFFFFFFFFL:
                dir_header.csize = zip64_extra.counts[idx]
                idx += 1

            if dir_header.relative_offset_file_header == 0xffffffffL:
                dir_header.relative_offset_file_header = zip64_extra.counts[idx]
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

    def write(self, filename, **kws):
        '''
        kws support:
            comment
            cryption
            compression_method
            zip64
            password
        '''
        offset = self.stream.tell()
        params = DictObject(kws)
        if params.password:
            self.password = params.password
        self.is_encrypted = True if self.password else False

        # set dir_header
        # ===============================================================
        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]
        dosdate = (date_time[0] - 1980) << 9 | date_time[1] << 5 | date_time[2]
        dostime = date_time[3] << 11 | date_time[4] << 5 | (date_time[5] // 2)
        # create file header
        flags = 0x800  # unicode file

        if self.password:
            flags = flags | 0x1
        if type(filename) == unicode:
            filename = filename.encode('utf8')

        packVals = DictObject({})
        packVals.last_mod_dos_datetime = (dostime, dosdate)
        packVals.general_purpose_bit_flag = flags
        packVals.filename_length = len(filename)
        packVals.filename = filename
        packVals.compression_method = params.compression_method
        packVals.file_comment = params.comment
        packVals.file_comment_length = len(params.comment)
        packVals.external_file_attributes = (st[0] & 0xFFFF) << 16L      # Unix attributes
        packVals.internal_file_attributes = 0
        compressed_data = ''

        if isdir:
            packVals.crc32 = 0
            packVals.external_file_attributes |= 0x10
        else:
            fd = open(filename, "rb")
            content = fd.read()
            close(fd)

            packVals.crc32 = zlib.crc32(content)

            # compress
            compressed_data = self._compress(content)
            # encrypt
            compressed_data = self._encrypt(compressed_data, self.password)
            if params.zip64:
                packVals.ucsize = packVals.csize = 0xFFFF
            else:
                packVals.ucsize = st.st_size
                packVals.csize = len(compressed_data)

        self.dir_header = struct_central_dir_header.pack(
            version_made_by=(20, 0),
            version_needed_to_extract=(20, 0),
            extra_field_length='',
            relative_offset_file_header='',
            extra_field='',
            **packVals.__dict__
        )

        # set self extras
        # ===============================================================
        extras = []
        # extra AES
        if self.password and params.cryption in ['AES_128', 'AES_192', 'AES_256']:
            extras.append(struct_extra_aes(
                data_length=7,
                vendor_version='AE_1',
                encrypt_strength=params.cryption,
                compression_method=Compressor.ZIP_DEFLATED,
            ))

        # extra ZIP64
        if params.zip64:
            extras.append(struct_extra_zip64(
                data_length=struct_extra_zip64.size(),
                ucsize=packVals.ucsize,
                csize=packVals.csize,
                relative_offset_file_header=offset,
            ))
        self.extra = ZipExtra(extras=extras)

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

    def _encrypt(self, data, password=None):
        if password == None:
            password = self.password

        if password:
            pass
        else:
            return data

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

    def getinfo(self, name):
        """Return the instance of ZipInfo given 'name'."""
        info = self._fileInfosDict.get(name)
        if info is None:
            raise KeyError(
                'There is no item named %r in the archive' % name)

        return info

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if isinstance(self.file, basestring):
            self.stream.close()

    def open(self):
        pass

    def read(self, item, password=None):
        if not password:
            password = self.password

        if isinstance(item, basestring):
            if item not in self._fileInfosDict:
                raise IOError('file not found', item)
            item = self._fileInfosDict[item]

        return item.read(password=password)


class ZipWriter(object):

    def __init__(self, file, **kws):
        '''
        kws supports:
            password = bytes
            cryption = 'ZIP', 'AES_128', 'AES_192', 'AES_256'
            compression_method = 'ZIP_DEFLATED', 'ZIP_STORED'
            zip64 = True | False
            comment = bytes

            fast
            good
        '''
        self.file = file
        if isinstance(file, basestring):
            self.filename = file
            self.stream = open(file, 'wb')
        else:
            self.filename = getattr(file, 'name')
            self.stream = file

        self._fileInfos = []
        self.params = DictObject(kws)

        self.password = None
        self.cryption = None
        self.compression_method = None
        self.zip64 = None
        self.comment = None

    def writestr(self, filename, content):
        pass

    def write(self, filename, **kws):
        '''
        kws support
            comment
        '''

        kws['compression_method'] = self.compression_method
        kws['cryption'] = self.cryption
        kws['zip64'] = self.zip64

        zipInfo = ZipInfo(self.stream, password=self.password)
        zipInfo.pack(filename, **kws)
        # self._fileInfos.append(zipInfo)

        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]
        # create file header
        flags = 0x800  # unicode file
        if self.password:
            flags = flags ^ 0x1
        if type(filename) == unicode:
            filename = filename.encode('utf8')

        dosdate = (date_time[0] - 1980) << 9 | date_time[1] << 5 | date_time[2]
        dostime = date_time[3] << 11 | date_time[4] << 5 | (date_time[5] // 2)

        dir_header = struct_central_dir_header.pack(
            version_made_by='',
            version_needed_to_extract='',
            general_purpose_bit_flag='',
            compression_method='',
            last_mod_dos_datetime='',
            crc32='',
            csize='',
            ucsize='',
            filename_length=len(filename),
            extra_field_length='',
            file_comment_length='',
            dist_index_file_start='',
            internal_file_attributes='',
            external_file_attributes='',
            relative_offset_file_header='',
            filename=filename,
            extra_field='',
            file_comment=''
        )
        # struct_local_file_header.pack(
        #     version_needed_to_extract=(20, 0),
        #     general_purpose_bit_flag=flags,
        #     compression_method=self.compression_method,
        #     last_mod_dos_datetime=(dostime, dosdate),
        #     crc32='',
        #     csize='',
        #     ucsize=,
        #     filename_length=,
        #     extra_field_length=,
        #     filename=,
        #     extra_field=,
        # )

        # create file data

        # create central dir header
        pass

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if isinstance(self.file, basestring):
            self.stream.close()
    #     zipInfo = ZipInfo()
    #     file_header, file_data, central_dir_header = zipInfo.write()
