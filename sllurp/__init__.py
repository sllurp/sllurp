"""Low Level Reader Protocol implemtnation in pure Python
"""

from pkg_resources import get_distribution


__all__ = ('llrp', 'llrp_decoder', 'llrp_errors', 'llrp_proto', 'util',
           'inventory')
__version__ = get_distribution('sllurp').version
