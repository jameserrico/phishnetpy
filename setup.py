#!/usr/bin/env python

from distutils.core import setup

VERSION = '0.1.1'

setup(name='phishnetpy',
      version=VERSION,
      description='Python client for the Phish.net API',
      author='James Errico',
      author_email='james.errico@gmail.com',
      url='https://github.com/jameserrico/phishnetpy',
      py_modules=['phisnetpy'],
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