class ExpectDict(object):
    def __init__(self, item, strict=False, noneable=False):
        '''
        if strict is True, keys must match all the times
        '''
        self.item = item
        self.strict = strict
        self.noneable = noneable
        if type(self.item) != dict:
            raise Exception('ExpectDict needs dict argumnet')

    def validate(self, val):
        if self.noneable and val is None:
            return
        assert type(val) == dict, 'except dict'
        if self.strict:
            assert len(self.item.keys()) == len(val.keys()), u'dict keys `{}` is not match `{}` in strict mode'.format(val.keys(), self.item.keys())
        for k, v in self.item.iteritems():
            if type(v) in [int, bool, str, unicode]:
                assert type(val.get(k)) == type(v), u'dict item `{}` except {}({}), but got {}({})'.format(k, v, type(v), val.get(k), type(val.get(k)))
                assert val.get(k) == v, u'dict item `{}` except {}({}), but got {}({})'.format(k, v, type(v), val.get(k), type(val.get(k)))
            elif hasattr(v, 'validate'):
                try:
                    v.validate(val.get(k))
                except AssertionError as err:
                    raise AssertionError(u'dict item `{}` '.format(k) + err.message)
            elif v in [int, bool, str, unicode]:
                assert type(val.get(k)) == v, u'dict item `{}` except type {}, but got {}'.format(k, v, type(val.get(k)))


class ExpectBool(object):
    def __init__(self, noneable=False):
        self.noneable = noneable

    def validate(self, val):
        if self.noneable and val is None:
            return
        assert type(val) == bool, u'except {}, but got {}'.format(bool, type(val))


class ExpectInt(object):
    def __init__(self, min=None, max=None, enum=None, noneable=False):
        self.min = min
        self.max = max
        self.enum = enum
        self.noneable = noneable

    def validate(self, val):
        if self.noneable and val is None:
            return
        assert type(val) == int, u'except {}, but got {}'.format(int, type(val))

        if self.min is not None:
            assert val >= self.min, u'int value {} is less then min value {}'.format(val, self.min)
        if self.max is not None:
            assert val < self.max, u'int value {} is great then max value {}'.format(val, self.max)
        if self.enum:
            assert val in self.enum, u'value must be one of {}'.format(self.enum)


class ExpectStr(object):
    def __init__(self, min_length=None, max_length=None, enum=None, noneable=False):
        self.min_length = min_length
        self.max_length = max_length
        self.enum = enum
        self.noneable = noneable

    def validate(self, val):
        if self.noneable and val is None:
            return
        assert type(val) in [str, unicode], u'except {}, but got {}'.format(str, type(val))

        if self.min_length is not None:
            assert len(val) >= self.min_length, u'str length {} is less then min length {}'.format(len(val), self.min_length)
        if self.max_length is not None:
            assert len(val) < self.max_length, u'str length {} is great then max length {}'.format(len(val), self.max_length)
        if self.enum:
            assert val in self.enum, u'value must be one of {}'.format(self.enum)


class ExpectList(object):
    def __init__(self, item=None, min_length=None, max_length=None, strict=False, noneable=False):
        self.min_length = min_length
        self.max_length = max_length
        self.noneable = noneable
        self.item = item

        self.expect = None
        if type(self.item) == dict:
            self.expect = ExpectDict(self.item, strict=strict)
        elif type(self.item) in [list, tuple]:
            self.expect = ExpectList(self.item[0] if len(self.item) else None)
        elif self.item == int:
            self.expect = ExpectInt()
        elif self.item == str:
            self.expect = ExpectStr()
        elif self.item == bool:
            self.expect = ExpectBool()
        elif isinstance(self.item, ExpectDict) or \
                isinstance(self.item, ExpectList) or \
                isinstance(self.item, ExpectInt) or \
                isinstance(self.item, ExpectStr) or \
                isinstance(self.item, ExpectBool):
            self.expect = self.item

    def validate(self, val):
        if self.noneable and val is None:
            return
        assert type(val) in [list, tuple], 'except {} or {}, but got {}'.format(list, tuple, type(val))
        if self.min_length is not None:
            assert len(val) >= self.min_length, 'list or tuple length {} is less then min length {}'.format(len(val), self.min_length)
        if self.max_length is not None:
            assert len(val) < self.max_length, 'list or tuple length {} is great then max length {}'.format(len(val), self.max_length)

        if self.expect:
            for item in val:
                self.expect.validate(item)
