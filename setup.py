#!/usr/bin/env python2

from setuptools import setup, find_packages
import os
import codecs

here = os.path.abspath(os.path.dirname(__file__))


def read(filename):
    """
    Get the long description from a file.
    """
    fname = os.path.join(here, filename)
    with codecs.open(fname, encoding='utf-8') as f:
        return f.read()


test_deps = ['nose2', 'flake8']
install_deps = [
    'click',
    'twisted',
    'six',
]


setup(
    name='sllurp',
    version='0.2.3',
    description='RFID reader control library',
    long_description=read('README.rst'),
    author='Ben Ransford',
    author_email='ben@ransford.org',
    url='https://github.com/ransford/sllurp',
    license='GPLv3',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='llrp rfid reader',
    packages=find_packages(),
    install_requires=install_deps,
    tests_require=test_deps,
    extras_require={'test': test_deps},
    test_suite='nose2.collector.collector',
    entry_points={
        'console_scripts': [
            'sllurp=sllurp.cli:cli',
        ],
    },
)
