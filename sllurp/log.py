"""
Logging setup
"""

from __future__ import unicode_literals
import logging
import sys
# Global
general_debug_enabled = False

def set_general_debug(debug=False):
    global general_debug_enabled
    general_debug_enabled = debug

def is_general_debug_enabled():
    return general_debug_enabled

def init_logging(debug=False, logfile=None, stream="stderr"):
    """Initialize logging."""
    set_general_debug(debug)

    loglevel = logging.DEBUG if debug else logging.INFO
    logformat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = logging.Formatter(logformat)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stdout_handler.setFormatter(formatter)
    stderr_handler.setFormatter(formatter)
    lower_than_warning = MaxLevelFilter(logging.WARNING)
    stdout_handler.addFilter(lower_than_warning)  # messages lower than WARNING go to stdout
    stdout_handler.setLevel(loglevel)
    stderr_handler.setLevel(max(loglevel, logging.WARNING))  # messages >= WARNING ( and >= STDOUT_LOG_LEVEL ) go to stderr

    root = logging.getLogger()
    root.setLevel(loglevel)
    root.addHandler(stderr_handler)
    root.addHandler(stdout_handler)

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


class MaxLevelFilter(logging.Filter):
    '''Filters (lets through) all messages with level < LEVEL'''
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno < self.level # "<" instead of "<=": since logger.setLevel is inclusive, this should be exclusive
