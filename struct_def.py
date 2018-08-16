from util.formater import *


class Signature:
    EXTRA_ZIP64 = 0x0001
    EXTRA_UPEF = 0x7075
    EXTRA_AES = 0x9901

    CENTRAL_RECORD = b'PK\x05\x06'
    CENTRAL_HEADER = b"PK\x01\x02"

    FILE_HEADER = b"PK\x03\x04"

    ZIP64_LOCATOR = b"PK\x06\x07"
    ZIP64_RECORD = b"PK\x06\x06"

    ZIP_RECORD = b'PK\x05\x06'


struct_end_central_dir_record = Struct(
    Const('signature', Signature.CENTRAL_RECORD),
    Int16ul('disk_index'),
    Int16ul('disk_index_width_start_central_dir'),
    Int16ul('total_entries_central_dir_disk'),
    Int16ul('total_entries_central_dir'),
    Int32ul('size_central_dir'),
    Int32ul('offset_start_central_dir'),
    Int16ul('zipfile_comment_length'),
    Bytes('zipfile_comment', 'zipfile_comment_length'),
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
    Int32ul("relative_offset_local_header"),
    Bytes("filename", 'filename_length'),
    Bytes("extra_field", 'extra_field_length'),
    Bytes("file_comment", 'file_comment_length')
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
    Bytes("filename", 'filename_length'),
    Bytes("extra_field", 'extra_field_length')
)

struct_zip64_central_dir_locator = Struct(
    Const("signature", Signature.ZIP64_LOCATOR),
    Int32ul("disk_index_width_zip64_central_dir_record"),
    Int64ul("offset_zip64_central_dir_record"),
    Int32ul("disk_total"),
)

struct_zip64_central_dir_record = Struct(
    Const("signature", Signature.ZIP64_RECORD),
    Int64ul("data_length"),
    Int8ul("version_made_by", size=2),
    Int8ul("version_needed_to_extract", size=2),
    Int32ul("disk_index"),
    Int32ul("disk_index_width_start_central_dir"),
    Int64ul("total_entries_central_dir_disk"),
    Int64ul("total_entries_central_dir"),
    Int64ul('size_central_dir'),
    Int64ul('offset_start_central_dir'),
    Bytes("extensible_data_sector", "data_length", -44)
    # zip64 extensible data sector (currently reserved for use by PKWARE)
)

struct_extra_header = Struct(
    Int16ul("signature"),
    Int16ul("data_length"),
)
# http://www.winzip.com/win/en/aes_info.htm#zip-format
# AES extra data struct

struct_extra_aes = Struct(
    Int16ul("signature"),
    Int16ul("data_length"),
    Int16ul("vendor_version"),
    Int8ul("vender_id", size=2),
    Int8ul("encrypt_strength", AES_128=1, AES_192=2, AES_256=3),
    Int16ul("compression_method")
)
# https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
# 4.6.9 -Info-ZIP Unicode Path Extra Field (0x7075):
struct_extra_upef = Struct(
    Int16ul("signature"),
    Int16ul("data_length"),
    Int8ul("version"),
    Int32ul("crc32"),
    Bytes("unicode_name", 'data_length', -5)
)

struct_extra_zip64 = Struct(
    Int16ul("signature"),
    Int16ul("data_length"),
    Int64ul("ucsize"),
    Int64ul("csize"),
    Int64ul("relative_offset_local_header"),
    Int32ul("disk_index"),
)
