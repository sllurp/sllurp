from inspect import stack

def BIT(n):
    return 1 << n

def BITMASK(n):
    return ((1 << (n)) - 1)

def func():
    "Return the current function's name."
    return stack()[1][3]

def hexlify (bs):
    "Return a hexadecimal representation of a byte sequence."
    return ''.join(['%02x' % ord(b) for b in bs])

def reverse_dict(data):
    atad = { }
    for m in data:
        i = data[m]
        atad[i] = m
    return atad
