from bisect import bisect_right
from inspect import stack
import re
from time import monotonic


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
    return [atoi(c) for c in re.split("([0-9]+)", text)]


def find_closest(table, target):
    """Return the greatest table entry not above target.

    Values below the first entry clamp to the first entry and values above the
    last entry clamp to the last entry. The table must be non-empty and sorted
    in ascending order.
    """
    if not table:
        raise ValueError("table must not be empty")

    index = bisect_right(table, target) - 1
    if index < 0:
        index = 0
    elif index >= len(table):
        index = len(table) - 1
    return index, table[index]
