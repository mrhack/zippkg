#!coding=utf8

from test.test import test_zipreader_normal, test_zipreader_crypt, test_zipwriter

from zippkg import ZipReader, ZipWriter
from util.crypt import PKWARECrypt, AESCrypt
from struct_def import *

if __name__ == '__main__':
    test_zipreader_normal()
    test_zipreader_crypt()

    test_zipwriter()
