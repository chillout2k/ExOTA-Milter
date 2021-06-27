import logging
import re
import os

def init_logger():
  log_level = logging.INFO
  if 'LOG_LEVEL' in os.environ:
    if re.match(r'^info$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.INFO
    elif re.match(r'^warn|warning$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.WARN
    elif re.match(r'^error$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.ERROR
    elif re.match(r'debug', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.DEBUG
  log_format = '%(asctime)s: %(levelname)s %(message)s '
  if log_level == logging.DEBUG:
    # Log thread-ID too. This helps to correlate DEBUG logs,
    # as Backend-logs do not have a queue_id nor a mconn_id!
    log_format = '%(asctime)s: %(levelname)s %(thread)d %(message)s '
  logging.basicConfig(
    filename = None, # log to stdout
    format = log_format,
    level = log_level
  )
  logging.info("Logger initialized")

def log_info(message):
  logging.info(message)

def log_error(message):
  logging.error(message)

def log_debug(message):
  logging.debug(message)