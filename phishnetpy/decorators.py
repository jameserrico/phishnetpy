__author__ = 'jerrico'

from phishnetpy.exceptions import AuthError

def qual_name_safe(f):
    try:
        return f.__qualname__
    except AttributeError:  # Occurs when Python <= 3.3
        from qualname import qualname
        return qualname(f)


def check_api_key(f):
    def wrapper(*args, **kwargs):
        if not args[0].api_key:
            raise AuthError("{} requires an API key".format(qual_name_safe(f)))
        return f(*args, **kwargs)
    return wrapper

def check_authorized_user(f):
    def wrapper(*args, **kwargs):
        if not args[0].api_key:
            raise AuthError("{} requires an API key".format(qual_name_safe(f)))
        if not args[0].username:
            raise AuthError("{} requires an authorized username".format(qual_name_safe(f)))
        if not args[0].auth_key:
            raise AuthError("{} requires an authkey".format(qual_name_safe(f)))
        return f(*args, **kwargs)
    return wrapper
