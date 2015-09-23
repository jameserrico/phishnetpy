__author__ = 'jerrico'

from phishnetpy.phishnet_api import PhishNetAPI
from phishnetpy import decorators
from phishnetpy import exceptions

# this package is part of setuptools
import pkg_resources

# the version is stored here upon initial installation
try:
    __version__ = pkg_resources.require("phishnetpy")[0].version
except pkg_resources.DistributionNotFound:
    # this will happen during local development
    # we should move the string to a TBD singular location
    __version__ = '0.2.4'
except:
    print('could not determine version!')
    raise
