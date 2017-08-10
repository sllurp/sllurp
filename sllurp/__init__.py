"""Low Level Reader Protocol implemtnation in pure Python
"""

from __future__ import unicode_literals
from pkg_resources import get_distribution


__all__ = ('llrp', 'llrp_decoder', 'llrp_errors', 'llrp_proto', 'util',
           'inventory')
__version__ = get_distribution('sllurp').version
