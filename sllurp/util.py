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
    return [atoi(c) for c in re.split('([0-9]+)', text)]


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
