"""
Logging setup
"""

from __future__ import unicode_literals
import logging


def init_logging(debug=False, logfile=None):
    logLevel = (debug and logging.DEBUG or logging.INFO)
    logFormat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = logging.Formatter(logFormat)
    stderr = logging.StreamHandler()
    stderr.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logLevel)
    root.handlers = [stderr]

    if logfile:
        fHandler = logging.FileHandler(logfile)
        fHandler.setFormatter(formatter)
        root.addHandler(fHandler)
