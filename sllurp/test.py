import unittest
import random
import sllurp, sllurp.llrp

def randhex (numdigits):
    """Return a string with numdigits hexadecimal digits."""
    assert type(numdigits) is int
    return '{{:0{}x}}'.format(numdigits).format(random.randrange(16**numdigits))

class TestROSpec (unittest.TestCase):
    def setUp (self):
        pass
    def test_start (self):
        rospec = sllurp.llrp.LLRPROSpec(1)
        rospec_str = repr(rospec)
        self.assertNotEqual(rospec_str, '')
    def tearDown (self):
        pass

if __name__ == '__main__':
    unittest.main()
