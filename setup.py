#!/usr/bin/env python

import codecs
import os
import re
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    fname = os.path.join(os.path.join(here, *parts))
    with codecs.open(fname, 'r', encoding='utf-8') as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


test_deps = ['pytest']
install_deps = [
    'click',
    'monotonic;python_version<"3.3"',
]


setup(
    name='sllurp',
    version=find_version('sllurp', 'version.py'),
    description='RFID reader control library',
    long_description=read('README.rst'),
    author='Ben Ransford',
    author_email='ben@ransford.org',
    url='https://github.com/sllurp/sllurp',
    maintainer='Florent Viard (github.com/fviard)',
    license='GPLv3',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords='llrp rfid reader',
    packages=find_packages(),
    install_requires=install_deps,
    tests_require=test_deps,
    extras_require={'test': test_deps},
    setup_requires=['pytest-runner'],
    entry_points={
        'console_scripts': [
            'sllurp=sllurp.cli:cli',
        ],
    },
)
