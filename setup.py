#!/usr/bin/env python2

from setuptools import setup
import codecs

# Get the long description from the relevant file
with codecs.open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = 'sllurp',
    version = '0.0.1',
    description = 'Python LLRP client',
    author = 'Ben Ransford',
    author_email = 'ransford@cs.washington.edu',
    url = 'https://github.com/ransford/sllurp',
    license = 'GPLv3',

    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Scientific/Engineering :: Information Analysis',        
    ],
    keywords = 'rfid llrpyc reader',
    packages = ['sllurp'],
    install_requires = ['twisted'],
    entry_points = {
        'console_scripts': [
            'inventory=sllurp.inventory:main',
        ],
    },
)
