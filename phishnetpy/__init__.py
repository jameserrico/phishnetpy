__author__ = 'jerrico'

from phishnetpy.phishnet_api import PhishNetAPI
from phishnetpy import decorators
from phishnetpy import exceptions

# this package is part of setuptools
import pkg_resources

# the version is stored here upon initial installation
__version__ = pkg_resources.require("phishnetpy")[0].version
