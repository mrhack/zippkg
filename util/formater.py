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

    def get_value(self, val):
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

    def _parse_stream_normal(self, stream, container, group):
        size = struct.calcsize(group.code)
        byte = stream.read(size)
        if len(byte) != size:
            raise FormatError("unpack requires a string argument of length {}".format(size))
        values = struct.unpack(group.code, byte)
        index = 0
        for f in group.fields:
            val = values[index: index+f.size]
            setattr(container, f.name, val if len(val) > 1 else f.get_value(val[0]))
            index += f.size

    def _parse_stream_bytes(self, stream, container, group):
        for f in group.fields:
            size = getattr(container, f.field, None)
            if size is None:
                raise FormatError("bytes need predefined field")

            setattr(container, f.name, stream.read(size + f.fix))

    def _parse_stream_const(self, stream, container, group):
        for f in group.fields:
            size = len(f.value)
            value = stream.read(size)
            if value != f.value:
                raise FormatError("const required `{}`, but got `{}`".format(repr(f.value), repr(value)))
            setattr(container, f.name, f.value)

    def parse_stream(self, stream):
        container = Container(self)

        for group in self.fields_groups:
            if group.type == _StructGroup.NORMAL:
                self._parse_stream_normal(stream, container, group)
            elif group.type == _StructGroup.BYTES:
                self._parse_stream_bytes(stream, container, group)
            elif group.type == _StructGroup.CONST:
                self._parse_stream_const(stream, container, group)

        return container
