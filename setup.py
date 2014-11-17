#!/usr/bin/env python
from distutils.core import setup
from setuptools import find_packages
import sys, os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

version = '0.1.0'

install_requires = open(os.path.join(here,"requirements.txt")).readline()

setup(name='lobo2',
      version=version,
      description="SUNET datasets",
      long_description=README,
      classifiers=[
          # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      ],
      keywords='sunet datasets torrent',
      author='Leif Johansson',
      author_email='leifj@sunet.se',
      url='http://blogs.mnt.se',
      license='BSD',
      setup_requires=['nose>=1.0'],
      tests_require=['nose>=1.0', 'mock', 'jinja2', 'mockredispy'],
      test_suite="nose.collector",
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      package_data={
          'lobo2': ['templates/*.html',
                    'static/**/*'],
      },
      zip_safe=False,
      install_requires=install_requires,
      message_extractors={'src': [
          ('**.py', 'python', None),
          ('**/templates/**.html', 'jinja2', None),
      ]},
)
