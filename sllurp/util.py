from __future__ import unicode_literals
from inspect import stack
import re
import sys

try:
    # monotonic available in time for Python > 3.3
    from time import monotonic
except ImportError:
    # For python2, monotonic package has to be installed.
    from monotonic import monotonic


PY3 = sys.version_info[0] == 3


def BIT(n):
    return 1 << n


def BITMASK(n):
    return (1 << (n)) - 1


def func():
    "Return the current function's name."
    return stack()[1][3]


def reverse_dict(data):
    return {value: key for key, value in data.items()}


def atoi(text):
    return int(text) if text.isdigit() else text


def natural_keys(text):
    """Sort alphanumerics in a "natural" order
    Source: https://stackoverflow.com/questions/5967500/

    >>> sorted(['foo25', 'foo3'], key=natural_keys)
    ['foo3', 'foo25']
    """
    return [atoi(c) for c in re.split('([0-9]+)', text)]

if PY3:
    def iteritems(d):
        return iter(d.items())

    def iterkeys(d):
        return iter(d.keys())

else:
    def iteritems(d):
        return d.iteritems()

    def iterkeys(d):
        return d.iterkeys()

def find_closest(table, target):
    left = 0
    right = len(table) - 1

    if target > table[right]:
        left = right
    else:
        # find the closest value in the conversion table
        while right != left + 1:
            middle = (left + right) // 2
            if table[middle] == target:
                left = middle
                break
            if table[middle] < target:
                left = middle
            if table[middle] > target:
                right = middle
    return left, table[left]
