

class Params:
    '''
    add dict key to instance's attribute, value to value
    '''

    def __init__(self, _dict):
        for k, v in _dict.iteritems():
            setattr(self, k, v)

    def __getattr__(self, key):
        return None
