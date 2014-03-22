#!/usr/bin/env python2

from setuptools import setup
import os
import re
import codecs

here = os.path.abspath(os.path.dirname(__file__))


def find_version(*file_paths):
    """
    Read the version number from a source file.
    Why read it, and not import?
    see https://groups.google.com/d/topic/pypa-dev/0PkjVpcxTzQ/discussion
    """
    with codecs.open(os.path.join(here, *file_paths), 'r', 'utf-8') as f:
        version_file = f.read()

    # The version line must have the form
    # __version__ = 'ver'
    version_match = re.search(r'^__version__ = [\'"]([^"\']*)["\']', version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


def read(filename):
    """
    Get the long description from a file.
    """
    with codecs.open(filename, encoding='utf-8') as f:
        return f.read()


setup(
    name='sllurp',
    version=find_version('sllurp', '__init__.py'),
    description=read('README.md'),
    author='Ben Ransford',
    author_email='ransford@cs.washington.edu',
    url='https://github.com/ransford/sllurp',
    license='GPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Scientific/Engineering :: Information Analysis',
    ],
    keywords='rfid llrpyc reader',
    packages=['sllurp'],
    install_requires=['twisted'],
    entry_points={
        'console_scripts': [
            'inventory=sllurp.inventory:main',
        ],
    },
)
