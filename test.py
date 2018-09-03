#!coding=utf8
from zippkg import ZipReader, ZipWriter


def test_zipreader_normal():
    print '-' * 20 + 'test_zipreader_normal' + '-' * 20
    paths = ['test-zips/compress-best.zip',
             'test-zips/compress-deflated.zip',
             'test-zips/compress-fast.zip',
             'test-zips/compress-good.zip',
             'test-zips/compress-mostfast.zip',
             'test-zips/compress-store.zip']

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
    paths = [('test-zips/compress-deflated-encrypto-aes-1234.zip', '1234'),
             ('test-zips/compress-deflated-encrypto-aes-unicode.zip', u'密码'.encode('gbk')),
             ('test-zips/compress-deflated-encrypto-zip-1234.zip', '1234'),
             ('test-zips/compress-deflated-encrypto-zip-unicode.zip', u'密码'.encode('gbk')),
             ('test-zips/compress-store-encrypto-aes-1234.zip', '1234'),
             ('test-zips/compress-store-encrypto-aes-unicode.zip', u'密码'.encode('gbk')),
             ('test-zips/compress-store-encrypto-zip-1234.zip', '1234'),
             ('test-zips/compress-store-encrypto-zip-unicode.zip', u'密码'.encode('gbk')),
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
    with ZipWriter('zipname.zip') as zipwriter:
        zipwriter.write('test.py')

        zipwriter.writestr('test/a/a.log', 'kwkw')

    with ZipReader('zipname.zip') as zipreader:
        for name in zipreader.namelist():
            print name, len(zipreader.read(name))


if __name__ == '__main__':
    test_zipreader_normal()
    test_zipreader_crypt()
    test_zipwriter()
