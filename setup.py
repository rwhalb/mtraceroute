#!/usr/bin/env python3
#-----------------------------------------------------------------------------
#   A setup.py installation script modified for 'mtraceroute.py'.
#-----------------------------------------------------------------------------
"""
A distutils Python setup file. For setuptools support see setup_egg.py.
"""
import os
import sys

from distutils.core import setup

if os.path.exists('MANIFEST'):
  os.remove('MANIFEST')

import release
#
#-----------------------------------------------------------------------------
def main():
  if sys.version_info[:2] < (3, 6):
    print("nstipgeolocate requires Python version 3.6.x or higher.")
    sys.exit(1)

  if sys.argv[-1] == 'setup.py':
    print("To install, run 'python3 setup.py install'")
    print()

  setup(
    name             = release.name,
    version          = release.version,
    description      = release.description,
    keywords         = release.keywords,
    download_url     = release.download_url,
    author           = release.author,
    author_email     = release.author_email,
    url              = release.url,
    packages         = release.packages,
    package_data     = release.package_data,
    license          = release.license,
    long_description = release.long_description,
    scripts          = release.scripts,
    platforms        = release.platforms,
    classifiers      = release.classifiers,
  )
#
#-----------------------------------------------------------------------------
if __name__ == "__main__":
  main()
