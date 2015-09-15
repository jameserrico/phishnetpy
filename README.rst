phishnetpy
==========

phishnetpy is a Python client for the `Phish.net
API <http://api.phish.net>`__. It works with either Python 2 or 3 and
supports all of the endpoints provided by api.phish.net.

Installation
============

You guessed it...

::

    pip install phishnetpy

Getting Started
===============

As you browse the `Phish.net API
documentation <http://api.phish.net/docu/>`__ you will see that some API
methods are labeled as "protected". This means that in order to use
those methods, you must generate an Application Key. To allow both
public and protected usage, there are several setup steps you have to
complete.

Public API Methods
------------------

For "public" or "unprotected" API calls, you simply need to instantiate
the PhishNetAPI class, and call the methods for each of the API methods.

.. code:: python

    >>> from phishnetpy import PhishNetAPI
    >>> phishnet = PhishNetAPI()
    >>> artists = phishnet.artists_get()
    >>> artists
    [{'artist': 'Phish', 'slug': 'phish', 'artistid': '1'}, {'artist': 'Trey Anastasio', 'slug': 'trey-anastasio-band', 'artistid': '2'}, {'artist': 'Mike Gordon', 'slug': 'mike-gordon', 'artistid': '6'}, {'artist': 'Jon Fishman', 'slug': 'jon-fishman', 'artistid': '7'}, {'artist': 'Page McConnell', 'slug': 'page-mcconnell', 'artistid': '9'}]

Attempting to call protected methods without passing in an API key into
the constructor will raise ``phishnetpy.exceptions.AuthError``.

.. code:: python

    >>> phishnet.user_username_check("wilson")
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "./phishnetpy/phishnetpy/decorators.py", line 16, in wrapper
        raise AuthError("{} requires an API key".format(qual_name_safe(f)))
    phishnetpy.exceptions.AuthError: PhishNetAPI.user_username_check requires an API key

Protected API Methods
---------------------

In order to collect "protected" API methods, you must pass an API key
into the constuctor.

.. code:: python

    >>> from phishnetpy import PhishNetAPI
    >>> my_api_key = "<MY API KEY>" # Private API key from http://api.phish.net/keys/
    >>> phishnet = PhishNetAPI(api_key=my_api_key)
    >>> phishnet.user_username_check("wilson")
    {'success': '0', 'reason': 'Sorry! wilson is already taken.'}

Methods requiring user authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some protected methods additionally require an auth\_key to take actions
on behalf of specific users. This includes submitting reviews, forum
threads, or adding a show to "My Shows".

phishnetpy can make generating auth codes simpler by adding some logic
on top of the ``pnet.api.*`` API methods.

The simplest way is probably by using the ``authorize`` method. In order
to make this method work, you will need both the username and password
of the user you are authorizing (at least the first time).

.. code:: python

    >>> from phishnetpy import PhishNetAPI
    >>> my_api_key = "<MY API KEY>" # Private API key from http://api.phish.net/keys/
    >>> phishnet = PhishNetAPI(api_key=my_api_key)
    >>> phishnet.authorize('authorized_username', 'that_users_password')

If unsuccessful, the ``phishnetpy.exceptions.AuthError`` will be raised.
If successful, the authorized username and auth key will be stored as
attributes on the instance you're working with.

.. code:: python

    >>> phishnet.username
    'authorized_username'
    >>> phishnet.auth_key
    'ABCD123456789012345'

Once those attributes have been set, you can make user-authorized API
calls. For example, lets add, and then remove `Halloween
2014 <http://phish.net/setlists/?d=2014-10-31>`__ to my shows.

.. code:: python

    >>> len(phishnet.user_myshows_get_authorized())
    7
    >>> phishnet.user_myshows_add('2014-10-31')
    {'success': 1}
    >>> len(phishnet.user_myshows_get_authorized())
    8
    >>> phishnet.user_myshows_remove('2014-10-31')
    {'success': 1}
    >>> len(phishnet.user_myshows_get_authorized())
    7

Once authorized, you should not store the user's password (per the
Phish.net terms).

.. |Build Status| image:: https://travis-ci.org/jameserrico/phishnetpy.svg?branch=master
   :target: https://travis-ci.org/jameserrico/phishnetpy