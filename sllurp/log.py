"""
Logging setup
"""

from __future__ import unicode_literals
import logging

# Global
general_debug_enabled = False

def set_general_debug(debug=False):
    global general_debug_enabled
    general_debug_enabled = debug

def is_general_debug_enabled():
    return general_debug_enabled

def init_logging(debug=False, logfile=None):
    """Initialize logging."""
    set_general_debug(debug)

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

def debugfast(self, *args, **kwargs):
    """logging debug func that is more efficient when debug is disabled.

    Even if disabled, logging debug will to check with isEnabledFor if it has
    something to do. That can cause a very very small lag but that could be
    noticable with a high rate of calls.
    """
    if general_debug_enabled:
        self.debug(*args, **kwargs)

def get_logger(module_name):
    """Return a logger object providing the custom debugfast function.

    Inject a sllurp specific debugfast function inside the current
    LoggerClass.
    """
    logger_cls = logging.getLoggerClass()
    logger_cls.debugfast = debugfast
    logger = logging.getLogger(module_name)
    return logger
