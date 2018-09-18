"""
Logging setup
"""

from __future__ import unicode_literals
import logging


def init_logging(debug=False, logfile=None):
    """Initialize logging."""
    loglevel = logging.DEBUG if debug else logging.INFO
    logformat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = logging.Formatter(logformat)
    stderr = logging.StreamHandler()
    stderr.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(loglevel)
    root.handlers = [stderr]

    if logfile:
        fhandler = logging.FileHandler(logfile)
        fhandler.setFormatter(formatter)
        root.addHandler(fhandler)
