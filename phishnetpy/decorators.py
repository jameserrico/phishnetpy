__author__ = 'jerrico'

from phishnetpy.exceptions import AuthError


def check_api_key(f):
    def wrapper(*args, **kwargs):
        if not args[0].api_key:
            raise AuthError("{} requires an API key".format(f.__qualname__))
        return f(*args, **kwargs)
    return wrapper

def check_authorized_user(f):
    def wrapper(*args, **kwargs):
        if not args[0].api_key:
            raise AuthError("{} requires an API key".format(f.__qualname__))
        if not args[0].username:
            raise AuthError("{} requires an authorized username".format(f.__qualname__))
        if not args[0].auth_key:
            raise AuthError("{} requires an authkey".format(f.__qualname__))
        return f(*args, **kwargs)
    return wrapper
