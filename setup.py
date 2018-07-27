#!/usr/bin/env python

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


test_deps = ['pytest']
install_deps = [
    'click',
    'monotonic',
    'twisted',
    'six',
]


setup(
    name='sllurp',
    version='0.4.2',
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
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
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
