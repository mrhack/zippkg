import struct
from . import DictObject


class FormatError(Exception):
    pass


class __Format(object):
    def __init__(self, name, fmt=None, size=1, **kws):
        self.name = name
        self.size = size
        if fmt:
            self.fmt = fmt if size == 1 else '{}{}'.format(size, fmt)
        else:
            self.fmt = None
        self.value = None

    def validate(self, value):
        pass

    def default(self):
        pass


class _NumFormat(__Format):
    types = [int]

    def __init__(self, name, fmt, size, **kws):
        super(_NumFormat, self).__init__(name, fmt, size)

        # k is str, v is int
        self.k2v = kws
        self.v2k = {}
        for k, v in kws.iteritems():
            self.v2k[v] = k

    def format_value(self, val):
        value = val
        desc = None
        if type(val) is str and self.k2v:
            value = self.k2v.get(val)
            desc = val
            if value is None:
                raise FormatError("`{}` do not match enum value `{}`".format(self.name, val))
        elif type(val) is int and self.v2k:
            value = val
            desc = self.v2k.get(val)
            if desc is None:
                raise FormatError("enum value `{}` is not exist".format(val))

        return value, desc

    def showValue(self, val):
        if type(val) in [list, tuple] and len(val) == 1:
            val = val[0]

        val, desc = self.format_value(val)
        return desc if desc else val

    def getValue(self, val):
        if type(val) == str:
            return self.k2v.get(val, 0)
        else:
            return val

    def validate(self, val):
        if self.size > 1:
            if type(val) not in [tuple, list]:
                raise FormatError("`{}` must be a tuple or list".format(self.name))
            elif len(val) != self.size:
                raise FormatError("`{}` got wrong size, size is {}".format(self.name, self.size))
        elif type(val) is str and self.k2v:
            if self.k2v.get(val) is None:
                raise FormatError("`{}` do not match enum value `{}`".format(self.name, val))
        elif type(val) is int and self.v2k:
            if self.v2k.get(val) is None:
                raise FormatError("enum value `{}` is not exist".format(val))
        elif type(val) not in self.types:
            raise FormatError("`{}` must be a number".format(self.name))

        return True

    def default(self):
        val = (0,) * self.size
        return val[0] if self.size == 1 else val


class Int8ul(_NumFormat):
    def __init__(self, name, size=1, **kws):
        super(Int8ul, self).__init__(name, 'B', size, **kws)


class Int16ul(_NumFormat):
    def __init__(self, name, size=1, **kws):
        super(Int16ul, self).__init__(name, 'H', size, **kws)


class Int32ul(_NumFormat):
    def __init__(self, name, size=1, **kws):
        super(Int32ul, self).__init__(name, 'L', size, **kws)


class Int64ul(_NumFormat):
    types = [int, long]

    def __init__(self, name, size=1, **kws):
        super(Int64ul, self).__init__(name, 'Q', size, **kws)


class Bytes(__Format):
    def __init__(self, name, field):
        super(Bytes, self).__init__(name)
        self.field = None
        self.size = 0

        if type(field) == int:
            self.size = field
        else:
            self.field = field

    def validate(self, val):
        if type(val) != str:
            raise FormatError("bytes `{}` got wrong type".format(self.name))
        elif self.size and len(val) != self.size:
            raise FormatError("bytes `{}` got wrong size".format(self.name))

        return True

    def default(self):
        return '\x00' * self.size


class Const(__Format):
    def __init__(self, name, value):
        super(Const, self).__init__(name)
        self.value = value

    def validate(self, val):
        if type(val) != str:
            raise FormatError("const `{}` got wrong type".format(self.name))
        elif self.value != val:
            raise FormatError("const `{}` got wrong value".format(self.name))

        return True

    def default(self):
        return self.value


class ThisItem(object):
    def __init__(self, name):
        self.name = name
        self.variable = 0

    def __add__(self, other):
        self.variable = other
        return self

    def __sub__(self, other):
        self.variable = -other
        return self


class This(object):
    def __getattr__(self, key):
        return ThisItem(key)


this = This()


class Container(object):
    def __init__(self, struct):
        self.__fields__ = struct.fields
        self.__struct__ = struct

    def size(self):
        size = 0
        for group in self.__struct__.fields_groups:
            if group.type == _FormatGroup.BYTES:
                for f in group.fields:
                    size += len(getattr(self, f.name))
            else:
                size += group.calcsize()

        return size

    def pack(self):
        content = ''
        for group in self.__struct__.fields_groups:
            content += group.pack(self)
        return content

    def __eq__(self, other):
        for f in self.__fields__:
            if getattr(self, f.name) != getattr(other, f.name):
                return False
        return True

    def __repr__(self):
        out = [str(self.__class__)[:-2].split('.')[-1] + ':']
        for f in self.__fields__:
            val = getattr(self, f.name)
            if isinstance(f, Bytes) or isinstance(f, Const):
                if isinstance(val, str):
                    size = len(val)
                    if size > 100:
                        val = val[:100] + '...'
                    val = 'b' + repr(val) + ' (total ' + str(size) + ')'
                elif isinstance(val, unicode):
                    size = len(val)
                    if size > 100:
                        val = val[:100] + '...'
                    val = repr(val) + ' (total ' + str(size) + ')'
            else:
                if f.getValue(val) != val:
                    val = '{}({})'.format(f.getValue(val), val)
            out.append('{}{} = {}'.format(' ' * 4, f.name, val))
        return "\n".join(out)


class _FormatGroup(object):
    NORMAL = 0
    BYTES = 1
    CONST = 2

    def __init__(self, type):
        self.type = type
        self.fields = []

    def calccode(self):
        if self.type == self.NORMAL:
            code = '<'
            for f in self.fields:
                code += f.fmt
        else:
            code = None
        self.code = code

    def calcsize(self):
        if self.type == _FormatGroup.NORMAL:
            return struct.calcsize(self.code)
        elif self.type == _FormatGroup.BYTES:
            size = 0
            for f in self.fields:
                size += f.size
            return size
        elif self.type == _FormatGroup.CONST:
            size = 0
            for f in self.fields:
                size += len(f.value)
            return size

    def _parseStreamNormal(self, stream, container):
        size = struct.calcsize(self.code)
        byte = stream.read(size)
        if len(byte) != size:
            raise FormatError("unpack requires a string argument of length {}".format(size))
        values = struct.unpack(self.code, byte)
        index = 0
        for f in self.fields:
            val = values[index: index+f.size]
            setattr(container, f.name, f.showValue(val))
            index += f.size

    def _parseStreamBytes(self, stream, container):
        for f in self.fields:
            if f.field:
                size = getattr(container, f.field.name, None)
                if size is None:
                    raise FormatError("bytes `{}` need predefined field or size".format(f.name))
                size += f.field.variable
            else:
                size = f.size

            setattr(container, f.name, stream.read(size))

    def _parseStreamConst(self, stream, container):
        for f in self.fields:
            size = len(f.value)
            value = stream.read(size)
            if value != f.value:
                raise FormatError("const required `{}`, but got `{}`".format(repr(f.value), repr(value)))
            setattr(container, f.name, f.value)

    def parseStream(self, stream, container):
        if self.type == _FormatGroup.NORMAL:
            self._parseStreamNormal(stream, container)
        elif self.type == _FormatGroup.BYTES:
            self._parseStreamBytes(stream, container)
        elif self.type == _FormatGroup.CONST:
            self._parseStreamConst(stream, container)

    def _packNormal(self, params):
        vals = []
        for f in self.fields:
            val = getattr(params, f.name)
            val = f.default() if val is None else val
            f.validate(val)
            if f.size > 1:
                vals += val
            else:
                vals.append(f.getValue(val))

        return struct.pack(self.code, *vals)

    def _packBytes(self, params):
        content = ''
        for f in self.fields:
            val = getattr(params, f.name) or ''
            f.validate(val)

            # check size
            if f.field:
                define_size = getattr(params, f.field.name)
                if define_size is None:
                    define_size = 0
                define_size += f.field.variable
            else:
                define_size = f.size
            if define_size is None:
                raise FormatError("bytes `{}` need predefined field".format(f.name))
            elif getattr(params, f.name) is None and f.size > 0:
                raise FormatError("bytes `{}` required".format(f.name))
            elif define_size != len(val):
                raise FormatError("bytes `{}` length is not correct".format(f.name))

            content += val
        return content

    def _packConst(self, params):
        content = ''
        for f in self.fields:
            val = getattr(params, f.name)
            if val is not None:
                f.validate(val)

            if val and val != f.value:
                raise FormatError("const `{}` got wrong value".format(f.name))
            content += f.value
        return content

    def pack(self, params):
        if self.type == _FormatGroup.NORMAL:
            return self._packNormal(params)
        elif self.type == _FormatGroup.BYTES:
            return self._packBytes(params)
        elif self.type == _FormatGroup.CONST:
            return self._packConst(params)

    def __repr__(self):
        return '<_FormatGroup type={}, code={}, fields={}>'.format(self.type, self.code, len(self.fields))


class Struct(object):

    def __init__(self, *fields):
        self.fields = fields
        self.fields_groups = []

        group = _FormatGroup(_FormatGroup.NORMAL)
        for f in fields:
            if isinstance(f, Bytes):
                if group.type != _FormatGroup.BYTES:
                    if group.fields:
                        group.calccode()
                        self.fields_groups.append(group)
                    group = _FormatGroup(_FormatGroup.BYTES)
            elif isinstance(f, Const):
                if group.type != _FormatGroup.CONST:
                    if group.fields:
                        group.calccode()
                        self.fields_groups.append(group)
                    group = _FormatGroup(_FormatGroup.CONST)
            else:
                if group.type != _FormatGroup.NORMAL:
                    if group.fields:
                        group.calccode()
                        self.fields_groups.append(group)
                    group = _FormatGroup(_FormatGroup.NORMAL)
            group.fields.append(f)

        if group.fields:
            group.calccode()
            self.fields_groups.append(group)

    def size(self):
        size = 0
        for group in self.fields_groups:
            size += group.calcsize()

        return size

    def parseStream(self, stream):
        container = Container(self)
        for group in self.fields_groups:
            group.parseStream(stream, container)
        return container

    def __call__(self, **kws):
        container = Container(self)
        for f in self.fields:
            val = kws.get(f.name)
            val = f.default() if val is None else val
            f.validate(val)
            if isinstance(f, Const):
                pass
            elif isinstance(f, Bytes):
                if f.field and kws.get(f.field.name, 0) + f.field.variable != len(val):
                    raise FormatError("bytes `{}` got the wrong size".format(f.name))
            else:
                val = f.showValue(val)
            setattr(container, f.name, val)
        return container

    def pack(self, **kws):
        params = DictObject(kws)
        content = ''
        for group in self.fields_groups:
            content += group.pack(params)
        return content
