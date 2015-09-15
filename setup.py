#!/usr/bin/env python

from distutils.core import setup
from pip.req import parse_requirements
from pip.download import PipSession

VERSION = '0.1.6'

install_reqs = parse_requirements('requirements.txt', session=PipSession())
reqs = [str(ir.req) for ir in install_reqs]


setup(name='phishnetpy',
      version=VERSION,
      description='Python client for the Phish.net API',
      author='James Errico',
      author_email='james.errico@gmail.com',
      url='https://github.com/jameserrico/phishnetpy',
      packages=['phishnetpy'],
      install_requires=reqs,
      license='MIT',
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.4',
      ],
)
