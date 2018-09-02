#!coding=utf8
"""
Read and write ZIP files.
"""
import os
import stat
import zlib
import time

from util import DictObject, BadZipfile, expect
from util.compress import Compressor
from util.crypt import Crypt
from zipextra import ZipExtra
from zipinfo import ZipInfo

from struct_def import *

ZIP64_FILESIZE_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1


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
        self.zipfile_comment = ''
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
        self.zipfile_comment = end_central_dir.zipfile_comment

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

            zinfo = ZipInfo(stream, password=self.password)
            zinfo.readHeader()
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

    KWS_DEFAULT = dict(
        password=None,
        cryption=None,
        compression_method=Compressor.ZIP_DEFLATED,
        zip64=False,
        comment=''
    )
    KWS_EXPECT = expect.ExpectDict({
        'password': expect.ExpectStr(noneable=True),
        'cryption': expect.ExpectStr(enum=Crypt.types, noneable=True),
        'compression_method': expect.ExpectInt(),
        'zip64': expect.ExpectBool(),
        'comment': expect.ExpectStr(noneable=True),
    }, strict=True)

    def __init__(self, file, **kws):
        '''
        kws supports:
            password = bytes
            cryption = 'ZIP', 'AES_128', 'AES_192', 'AES_256'
            compression_method = number
            zip64 = True | False
            comment = bytes

        '''
        self.file = file
        if isinstance(file, basestring):
            self.filename = file
            self.stream = open(file, 'wb')
        else:
            self.filename = getattr(file, 'name')
            self.stream = file

        self._fileInfos = []
        self._fileInfosDict = {}

        # expect
        default = self.KWS_DEFAULT.copy()
        default.update(kws)
        self.KWS_EXPECT.validate(default)
        for k, v in default.iteritems():
            setattr(self, k, v)
        if self.cryption and not self.password:
            raise Exception('needs password argument')

    def writestr(self, filename, content, comment='', date_time=None):
        zipinfo = ZipInfo(self.stream,
                          password=self.password,
                          comment=comment,
                          cryption=self.cryption,
                          compression_method=self.compression_method,
                          zip64=self.zip64)

        if date_time is None:
            date_time = time.localtime(time.time())[:6]
        zipinfo.write(
            filename,
            content=content,
            isdir=False,
            date_time=date_time)

        self._fileInfos.append(zipinfo)
        self._fileInfosDict[zipinfo.filename] = zipinfo

    def write(self, filename, comment=''):
        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]

        fd = open(filename)
        content = fd.read()
        fd.close()

        self.writestr(filename, content, comment=comment, date_time=date_time)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        # write central directory header
        central_directory_header_offset = self.stream.tell()
        for zipinfo in self._fileInfos:
            self.stream.write(zipinfo.dir_header.pack())

        # write end of central directory record
        self.end_central_dir = struct_end_central_dir_record(
            total_entries_central_dir_disk=len(self._fileInfos),
            total_entries_central_dir=len(self._fileInfos),
            size_central_dir=self.stream.tell() - central_directory_header_offset,
            offset_start_central_dir=central_directory_header_offset,
            zipfile_comment_length=len(self.comment),
            zipfile_comment=self.comment
        )
        self.stream.write(self.end_central_dir.pack())

        if isinstance(self.file, basestring):
            self.stream.close()
