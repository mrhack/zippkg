import zlib


class CompressError(Exception):
    pass


class _Com(object):
    def __init__(self):
        pass

    def compress(self, content):
        raise NotImplementedError("need rewrite")

    def decompress(self, content):
        raise NotImplementedError("need rewrite")


class _StoreCompressor(_Com):
    key = 0

    def __init__(self):
        super(_StoreCompressor, self).__init__()

    def compress(self, content):
        return content

    def decompress(self, content):
        return content


class _DeflatedCompressor(_Com):
    key = 8

    def __init__(self):
        super(_DeflatedCompressor, self).__init__()

    def compress(self, content):
        return zlib.compress(content, -15)

    def decompress(self, content):
        return zlib.decompress(content, -15)


class Compressor:
    _dict_ = {
        _StoreCompressor.key: _StoreCompressor,
        _DeflatedCompressor.key: _DeflatedCompressor,
    }

    def __init__(self, method):
        if not self._dict_.get(method):
            raise CompressError("compression method `{}` is not supported".format(method))
        self.handler = self._dict_.get(method)()

    def compress(self, content):
        return self.handler.compress(content)

    def decompress(self, content):
        return self.handler.decompress(content)
