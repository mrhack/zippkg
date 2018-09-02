#!coding=utf8
from zippkg import ZipReader, ZipWriter


def test_zipreader_normal():
    print '-' * 20 + 'test_zipreader_normal' + '-' * 20
    paths = ['../ziptest/zips/compress-best.zip',
             '../ziptest/zips/compress-deflated.zip',
             '../ziptest/zips/compress-fast.zip',
             '../ziptest/zips/compress-good.zip',
             '../ziptest/zips/compress-mostfast.zip',
             '../ziptest/zips/compress-store.zip']

    for path in paths:
        print 'file: ' + path
        with ZipReader(path) as zipreader:
            index = 0
            for name in zipreader.namelist():
                print index, name, len(zipreader.read(name))
                index += 1
        print ''


def test_zipreader_crypt():
    print '-' * 20 + 'test_zipreader_crypt' + '-' * 20
    paths = [('../ziptest/zips/compress-deflated-encrypto-aes-1234.zip', '1234'),
             ('../ziptest/zips/compress-deflated-encrypto-aes-unicode.zip', u'密码'.encode('gbk')),
             ('../ziptest/zips/compress-deflated-encrypto-zip-1234.zip', '1234'),
             ('../ziptest/zips/compress-deflated-encrypto-zip-unicode.zip', u'密码'.encode('gbk')),
             ('../ziptest/zips/compress-store-encrypto-aes-1234.zip', '1234'),
             ('../ziptest/zips/compress-store-encrypto-aes-unicode.zip', u'密码'.encode('gbk')),
             ('../ziptest/zips/compress-store-encrypto-zip-1234.zip', '1234'),
             ('../ziptest/zips/compress-store-encrypto-zip-unicode.zip', u'密码'.encode('gbk')),
             ]

    for path, password in paths:
        print 'file: ' + path
        with ZipReader(path, password=password) as zipreader:
            index = 0
            for name in zipreader.namelist():
                print index, name, len(zipreader.read(name))
                index += 1
        print ''


def test_zipwriter():
    with ZipWriter('zipname.zip', password="111", cryption="AES_256") as zipwriter:
        zipwriter.write('test.py')

        zipwriter.writestr('test/a/a.log', 'kwkw')

    with ZipReader('zipname.zip', password="111") as zipreader:
        for name in zipreader.namelist():
            print name, len(zipreader.read(name))
