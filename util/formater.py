import struct


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

    def __repr__(self):
        return '{}{}: {}'.format(' '*4, self.name, self.value)


class _IntFormat(__Format):
    def __init__(self, name, fmt, size, **kws):
        super(_IntFormat, self).__init__(name, fmt, size)

        self.enum = {}
        for k, v in kws.iteritems():
            self.enum[v] = k

    def getValue(self, val):
        return self.enum.get(val) if self.enum else val


class Int8ul(_IntFormat):
    def __init__(self, name, size=1, **kws):
        super(Int8ul, self).__init__(name, 'B', size, **kws)


class Int16ul(_IntFormat):
    def __init__(self, name, size=1, **kws):
        super(Int16ul, self).__init__(name, 'H', size, **kws)


class Int32ul(_IntFormat):
    def __init__(self, name, size=1, **kws):
        super(Int32ul, self).__init__(name, 'L', size, **kws)


class Int64ul(_IntFormat):
    def __init__(self, name, size=1, **kws):
        super(Int64ul, self).__init__(name, 'Q', size, **kws)


class Bytes(__Format):
    def __init__(self, name, field, fix=0):
        super(Bytes, self).__init__(name)
        self.field = None
        self.size = 0
        if type(field) == int:
            self.size = field
        else:
            self.field = field
        self.fix = fix


class Const(__Format):
    def __init__(self, name, value):
        super(Const, self).__init__(name)
        self.value = value


class Container(object):
    def __init__(self, struct):
        self.__fields__ = struct.fields
        self.__struct__ = struct

    def size(self):
        size = 0
        for group in self.__struct__.fields_groups:
            if group.type == _StructGroup.BYTES:
                for f in group.fields:
                    size += len(getattr(self, f.name))
            else:
                size += group.calcsize()

        return size

    def __repr__(self):
        out = [str(self.__class__)[:-2].split('.')[-1] + ':']
        for f in self.__fields__:
            val = getattr(self, f.name)
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
            out.append('{}{} = {}'.format(' ' * 4, f.name, val))
        return "\n".join(out)


class _StructGroup(object):
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
        if self.type == _StructGroup.NORMAL:
            return struct.calcsize(self.code)
        elif self.type == _StructGroup.BYTES:
            return 0
        elif self.type == _StructGroup.CONST:
            size = 0
            for f in self.fields:
                size += len(f.value)
            return size

    def __repr__(self):
        return '<_StructGroup type={}, code={}, fields={}>'.format(self.type, self.code, len(self.fields))


class Struct(object):

    def __init__(self, *fields):
        self.fields = fields
        self.fields_groups = []

        group = _StructGroup(_StructGroup.NORMAL)
        for f in fields:
            if isinstance(f, Bytes):
                if group.type != _StructGroup.BYTES:
                    if group.fields:
                        group.calccode()
                        self.fields_groups.append(group)
                    group = _StructGroup(_StructGroup.BYTES)
            elif isinstance(f, Const):
                if group.type != _StructGroup.CONST:
                    if group.fields:
                        group.calccode()
                        self.fields_groups.append(group)
                    group = _StructGroup(_StructGroup.CONST)
            else:
                if group.type != _StructGroup.NORMAL:
                    if group.fields:
                        group.calccode()
                        self.fields_groups.append(group)
                    group = _StructGroup(_StructGroup.NORMAL)
            group.fields.append(f)

        if group.fields:
            group.calccode()
            self.fields_groups.append(group)

    def size(self):
        size = 0
        for group in self.fields_groups:
            size += group.calcsize()

        return size

    def _parseStreamNormal(self, stream, container, group):
        size = struct.calcsize(group.code)
        byte = stream.read(size)
        if len(byte) != size:
            raise FormatError("unpack requires a string argument of length {}".format(size))
        values = struct.unpack(group.code, byte)
        index = 0
        for f in group.fields:
            val = values[index: index+f.size]
            setattr(container, f.name, val if len(val) > 1 else f.getValue(val[0]))
            index += f.size

    def _parseStreamBytes(self, stream, container, group):
        for f in group.fields:
            if f.field:
                size = getattr(container, f.field, None)
            else:
                size = f.size
            if size is None:
                raise FormatError("bytes `{}` need predefined field".format(f.name))

            setattr(container, f.name, stream.read(size + f.fix))

    def _parseStreamConst(self, stream, container, group):
        for f in group.fields:
            size = len(f.value)
            value = stream.read(size)
            if value != f.value:
                raise FormatError("const required `{}`, but got `{}`".format(repr(f.value), repr(value)))
            setattr(container, f.name, f.value)

    def parseStream(self, stream):
        container = Container(self)

        for group in self.fields_groups:
            if group.type == _StructGroup.NORMAL:
                self._parseStreamNormal(stream, container, group)
            elif group.type == _StructGroup.BYTES:
                self._parseStreamBytes(stream, container, group)
            elif group.type == _StructGroup.CONST:
                self._parseStreamConst(stream, container, group)

        return container

    def _packNormal(self, params, group):
        vals = []
        for f in group.fields:
            val = getattr(params, f.name)
            if val:
                if f.size > 1:
                    vals += val
                else:
                    vals.append(val)
            else:
                vals.append(0)

        return struct.pack(group.code, *vals)

    def _packBytes(self, params, group):
        content = ''
        for f in group.fields:
            con = getattr(params, f.name) or ''
            # check size
            if f.field:
                define_size = getattr(container, f.field, None)
            else:
                define_size = f.size
            if define_size is None:
                raise FormatError("bytes `{}` need predefined field".format(f.name))
            if define_size + f.fix != len(con):
                raise FormatError("bytes `{}` length is not correct".format(f.name))

            content += con
        return content

    def _packConst(self, params, group):
        content = ''
        for f in group.fields:
            content += getattr(params, f.name) or ''
        return content

    def pack(self, **kws):
        container = Container(self)
        params = Params(kws)
        content = ''
        for group in self.fields_groups:
            if group.type == _StructGroup.NORMAL:
                content += self._packNormal(params, group)
            elif group.type == _StructGroup.BYTES:
                content += self._packBytes(params, group)
            elif group.type == _StructGroup.CONST:
                content += self._packConst(params, group)
        return content
