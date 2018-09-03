from util.formater import *


class Signature:
    EXTRA_ZIP64 = b'\x01\x00'
    EXTRA_UPEF = b'\x75\x70'
    EXTRA_AES = b'\x01\x99'

    CENTRAL_RECORD = b'PK\x05\x06'
    CENTRAL_HEADER = b"PK\x01\x02"

    FILE_HEADER = b"PK\x03\x04"

    ZIP64_LOCATOR = b"PK\x06\x07"
    ZIP64_RECORD = b"PK\x06\x06"

    ZIP_RECORD = b'PK\x05\x06'


struct_end_central_dir_record = Struct(
    Const('signature', Signature.CENTRAL_RECORD),
    Int16ul('disk_index'),
    Int16ul('disk_index_with_start_central_dir'),
    Int16ul('total_entries_central_dir_disk'),
    Int16ul('total_entries_central_dir'),
    Int32ul('size_central_dir'),
    Int32ul('offset_start_central_dir'),
    Int16ul('zipfile_comment_length'),
    Bytes('zipfile_comment', this.zipfile_comment_length),
)

struct_central_dir_header = Struct(
    Const("signature", Signature.CENTRAL_HEADER),
    Int8ul("version_made_by", size=2),
    Int8ul("version_needed_to_extract", size=2),
    Int16ul("general_purpose_bit_flag"),
    Int16ul("compression_method"),
    Int16ul("last_mod_dos_datetime", size=2),  # last mod file time and last mod file date
    Int32ul("crc32"),
    Int32ul("csize"),  # compressed size
    Int32ul("ucsize"),  # uncompressed size
    Int16ul("filename_length"),
    Int16ul("extra_field_length"),
    Int16ul("file_comment_length"),
    Int16ul("dist_index_file_start"),
    Int16ul("internal_file_attributes"),
    Int32ul("external_file_attributes"),
    Int32ul("relative_offset_file_header"),
    Bytes("filename", this.filename_length),
    Bytes("extra_field", this.extra_field_length),
    Bytes("file_comment", this.file_comment_length)
)

struct_local_file_header = Struct(
    Const("signature", Signature.FILE_HEADER),
    Int8ul("version_needed_to_extract", size=2),
    Int16ul("general_purpose_bit_flag"),
    Int16ul("compression_method"),
    Int16ul("last_mod_dos_datetime", size=2),  # last mod file time and last mod file date
    Int32ul("crc32"),
    Int32ul("csize"),  # compressed size
    Int32ul("ucsize"),  # uncompressed size
    Int16ul("filename_length"),
    Int16ul("extra_field_length"),
    Bytes("filename", this.filename_length),
    Bytes("extra_field", this.extra_field_length)
)

struct_zip64_central_dir_locator = Struct(
    Const("signature", Signature.ZIP64_LOCATOR),
    Int32ul("disk_index_with_zip64_central_dir_record"),
    Int64ul("offset_zip64_central_dir_record"),
    Int32ul("disk_total"),
)

struct_zip64_central_dir_record = Struct(
    Const("signature", Signature.ZIP64_RECORD),
    Int64ul("data_length"),
    Int8ul("version_made_by", size=2),
    Int8ul("version_needed_to_extract", size=2),
    Int32ul("disk_index"),
    Int32ul("disk_index_with_start_central_dir"),
    Int64ul("total_entries_central_dir_disk"),
    Int64ul("total_entries_central_dir"),
    Int64ul('size_central_dir'),
    Int64ul('offset_start_central_dir'),
    Bytes("extensible_data_sector", this.data_length - 44)
    # zip64 extensible data sector (currently reserved for use by PKWARE)
)

struct_extra_header = Struct(
    Bytes("signature", 2),
    Int16ul("data_length"),
)

# http://www.winzip.com/win/en/aes_info.htm#zip-format
# AES extra data struct
struct_extra_aes = Struct(
    Const("signature", Signature.EXTRA_AES),
    Int16ul("data_length"),
    Int16ul("vendor_version", AE_1=1, AE_2=2),
    Const("vender_id", 'AE'),
    Int8ul("encrypt_strength", AES_128=1, AES_192=2, AES_256=3),
    Int16ul("compression_method")
)
# https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
# 4.6.9 -Info-ZIP Unicode Path Extra Field (0x7075):
struct_extra_upef = Struct(
    Const("signature", Signature.EXTRA_UPEF),
    Int16ul("data_length"),
    Int8ul("version"),
    Int32ul("crc32"),
    Bytes("unicode_name", this.data_length - 5)
)

struct_extra_zip64 = Struct(
    Const("signature", Signature.EXTRA_ZIP64),
    Int16ul("data_length"),
    Bytes('data', this.data_length),
    # Int64ul("ucsize"),
    # Int64ul("csize"),
    # Int64ul("relative_offset_file_header"),
    # Int32ul("disk_index"),
)


def pack_zip64_data(vals):
    packs = {
        1: '<Q',
        2: '<QQ',
        3: '<QQQ',
        4: '<QQQL',
    }
    if len(vals) in packs:
        return struct.pack(packs[len(vals)], *vals)
    return ''


def unpack_zip64_data(data):
    data_length = len(data)
    if data_length == 28:
        counts = struct.unpack('<QQQL', data)
    elif data_length == 24:
        counts = struct.unpack('<QQQ', data)
    elif data_length == 16:
        counts = struct.unpack('<QQ', data)
    elif data_length == 8:
        counts = struct.unpack('<Q', data)
    elif data_length == 0:
        counts = ()
    else:
        raise RuntimeError, "Corrupt extra field %s" % (data_length,)

    return counts
