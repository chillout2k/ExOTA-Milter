import Milter
import sys
import traceback
import os
import logging
import string
import random
import re
import email.utils
import authres
import json
from policy import (
  ExOTAPolicyException, ExOTAPolicyNotFoundException, 
  ExOTAPolicyBackendJSON, ExOTAPolicy
)

# Globals with mostly senseless defaults ;)
g_milter_name = 'exota-milter'
g_milter_socket = '/socket/' + g_milter_name
g_milter_reject_message = 'Security policy violation!'
g_milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
g_re_domain = re.compile(r'^.*@(\S+)$', re.IGNORECASE)
g_loglevel = logging.INFO
g_milter_dkim_enabled = False
g_milter_dkim_authservid = 'invalid'
g_milter_policy_source = 'file' # file, ldap, etc.
g_milter_policy_file = 'invalid'
g_milter_policy_backend = None

class ExOTAMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.reset()

  def reset(self):
    self.client_ip = None
    self.queue_id = None
    self.hdr_from = None
    self.hdr_from_domain = None
    self.hdr_tenant_id = None
    self.hdr_tenant_id_count = 0
    self.dkim_results = []
    self.dkim_valid = False
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )
    logging.debug(self.mconn_id + " RESET")

  # Not registered/used callbacks
  @Milter.nocallback
  def connect(self, IPname, family, hostaddr):
    return Milter.CONTINUE
  @Milter.nocallback
  def hello(self, heloname):
    return Milter.CONTINUE
  @Milter.nocallback
  def eoh(self):
    return Milter.CONTINUE
  @Milter.nocallback
  def body(self, chunk):
    return Milter.CONTINUE

  def envfrom(self, mailfrom, *str):
    # Instance member values remain within reused SMTP-connections!
    if self.client_ip is not None:
      # Milter connection reused!
      logging.debug(self.mconn_id + "/FROM connection reused!")
      self.reset()
    self.client_ip = self.getsymval('{client_addr}')
    if self.client_ip is None:
      logging.error(self.mconn_id + " FROM exception: could not retrieve milter-macro ({client_addr})!")
      self.setreply('550','5.7.1', g_milter_tmpfail_message)
      return Milter.REJECT
    else:
      logging.debug(self.mconn_id + "/FROM client_ip={0}".format(self.client_ip))
      return Milter.CONTINUE

  def envrcpt(self, to, *str):
    logging.debug(self.mconn_id + "/RCPT 5321.rcpt={0}".format(to))
    return Milter.CONTINUE

  def header(self, name, hval):
    logging.debug(self.mconn_id + "/" + str(self.queue_id) +
      "/HEADER Header: {0}, Value: {1}".format(name, hval)
    )

    # Parse RFC-5322-From header
    if(name == "From"):
      hdr_5322_from = email.utils.parseaddr(hval)
      self.hdr_from = hdr_5322_from[1].lower()
      m = re.match(g_re_domain, self.hdr_from)
      if m is None:
        logging.error(self.mconn_id  + "/" + str(self.queue_id) + "/HEADER " +
          "Could not determine domain-part of 5322.from=" + self.hdr_from
        )
        self.setreply('450','4.7.1', g_milter_tmpfail_message)
        return Milter.TEMPFAIL
      self.hdr_from_domain = m.group(1)
      logging.debug(self.mconn_id + "/" + str(self.queue_id) +
        "/HEADER 5322.from: {0}, 5322.from_domain: {1}".format(self.hdr_from, self.hdr_from_domain)
      )

    # Parse non-standardized X-MS-Exchange-CrossTenant-Id header
    elif(name == "X-MS-Exchange-CrossTenant-Id"):
      self.hdr_tenant_id_count += 1
      self.hdr_tenant_id = hval.lower()
      logging.debug(self.mconn_id + "/" + str(self.queue_id) +
        "/HEADER Tenant-ID: {0}".format(self.hdr_tenant_id)
      )

    # Parse RFC-7601 Authentication-Results header
    elif(name == "Authentication-Results"):
      if g_milter_dkim_enabled == True:
        ar = None
        try:
          ar = authres.AuthenticationResultsHeader.parse(
            "{0}: {1}".format(name, hval)
          )
          if ar.authserv_id == g_milter_dkim_authservid:
            for ar_result in ar.results:
              if ar_result.method == 'dkim':
                self.dkim_results.append({
                  "selector": str(ar_result.header_s),
                  "from_domain": str(ar_result.header_d),
                  "result": str(ar_result.result)
                })
          else:
            logging.debug(self.mconn_id + "/" + str(self.queue_id) +
              "/HEADER Ignoring authentication results of {0}".format(ar.authserv_id)
            )
        except:
          logging.error(self.mconn_id + "/" + str(self.queue_id) +
            "/HEADER AR-parse exception: " + traceback.format_exc()
          )
    return Milter.CONTINUE

  # EOM is not optional and thus always called by MTA
  def eom(self):
    # A queue-id will be generated after the first accepted RCPT TO
    # and therefore not available until DATA command
    self.queue_id = self.getsymval('i')
    if self.queue_id is None:
      logging.error(self.mconn_id + "EOM exception: could not retrieve milter-macro (i)!")
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    else:
      logging.debug(self.mconn_id + "/EOM Queue-ID: {0}".format(self.queue_id))
    
    if self.hdr_from is None:
      logging.error(self.mconn_id + "/" + self.queue_id +
        "/EOM exception: could not determine 5322.from header!"
      )
      self.setreply('550','5.7.1', g_milter_tmpfail_message)
      return Milter.REJECT

    # Get policy for 5322.from_domain
    policy = None
    try:
      policy = g_milter_policy_backend.get(self.hdr_from_domain)
      logging.debug(self.mconn_id + "/" + self.queue_id +
        "/EOM Policy for 5322.from_domain={0} fetched from backend".format(self.hdr_from_domain)
      )
    except (ExOTAPolicyException, ExOTAPolicyNotFoundException) as e:
      logging.info(self.mconn_id + "/" + self.queue_id +
        "/EOM {0}".format(e.message)
      )
      self.setreply('550','5.7.1', g_milter_tmpfail_message)
      return Milter.REJECT

    if self.hdr_tenant_id is None:
      logging.error(self.mconn_id + "/" + self.queue_id +
        "/EOM exception: could not determine X-MS-Exchange-CrossTenant-Id"
      )
      self.setreply('550','5.7.1', g_milter_reject_message)
      return Milter.REJECT
    if self.hdr_tenant_id_count > 1:
      logging.info(self.mconn_id + "/" + self.queue_id +
        "/EOM: More than one tenant-IDs for {0} found!".format(self.hdr_from_domain)
      )
      self.setreply('550','5.7.1', g_milter_reject_message)
      return Milter.REJECT
    if self.hdr_tenant_id == policy.get_tenant_id():
      logging.info(self.mconn_id + "/" + self.queue_id +
        "/EOM: 5322.from_domain={0} tenant_id={1} status=match".format(
          self.hdr_from_domain, self.hdr_tenant_id
        )
      )
    else:
      logging.error(self.mconn_id + "/" + self.queue_id +
        "/EOM: 5322.from_domain={0} tenant_id={1} status=no_match".format(
          self.hdr_from_domain, self.hdr_tenant_id
        )
      )
      self.setreply('550','5.7.1', g_milter_reject_message)
      return Milter.REJECT

    if g_milter_dkim_enabled and policy.is_dkim_enabled():
      logging.debug(self.mconn_id + "/" + self.queue_id +
        "/EOM: 5322.from_domain={0} dkim_auth=enabled".format(self.hdr_from_domain)
      )
      if len(self.dkim_results) > 0:
        for dkim_result in self.dkim_results:
          if dkim_result['from_domain'] == self.hdr_from_domain:
            logging.debug(self.mconn_id + "/" + self.queue_id +
              "/EOM: Found DKIM authentication result for {0}/{1}".format(
                self.hdr_from_domain, dkim_result['selector']
              )
            )
            if dkim_result['result'] == 'pass':
              logging.info(self.mconn_id + "/" + self.queue_id +
                "/EOM: 5322.from_domain={0} dkim_selector={1} result=pass".format(
                  self.hdr_from_domain, dkim_result['selector']
                )
              )
              self.dkim_valid = True
              continue
            else:
              logging.info(self.mconn_id + "/" + self.queue_id +
                "/EOM: 5322.from_domain={0} dkim_selector={1} result=fail".format(
                  self.hdr_from_domain, dkim_result['selector']
                )
              )
      else:
        logging.info(self.mconn_id + "/" + self.queue_id +
          "/EOM: No DKIM authentication results (AR headers) found!"
        )
        self.setreply('550','5.7.1', g_milter_reject_message)
        return Milter.REJECT
      if self.dkim_valid == False:
        logging.info(self.mconn_id + "/" + self.queue_id +
          "/EOM: DKIM authentication failed!"
        )
        self.setreply('550','5.7.1', g_milter_reject_message)
        return Milter.REJECT
        
    logging.info(self.mconn_id + "/" + self.queue_id +
      "/EOM: Authentication successful (dkim_enabled={0})".format(
        str(policy.is_dkim_enabled())
      )
    )
    return Milter.CONTINUE

  def abort(self):
    # Client disconnected prematurely
    logging.debug(self.mconn_id + "/ABORT")
    return Milter.CONTINUE

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    logging.debug(self.mconn_id + "/CLOSE")
    return Milter.CONTINUE

if __name__ == "__main__":
  if 'LOG_LEVEL' in os.environ:
    if re.match(r'^info$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.INFO
    elif re.match(r'^warn|warning$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.WARN
    elif re.match(r'^error$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.ERROR
    elif re.match(r'debug', os.environ['LOG_LEVEL'], re.IGNORECASE):
      g_loglevel = logging.DEBUG
  logging.basicConfig(
    filename=None, # log to stdout
    format='%(asctime)s: %(levelname)s %(message)s',
    level=g_loglevel
  )
  if 'MILTER_NAME' in os.environ:
    g_milter_name = os.environ['MILTER_NAME']
  if 'MILTER_SOCKET' in os.environ:
    g_milter_socket = os.environ['MILTER_SOCKET']
  if 'MILTER_REJECT_MESSAGE' in os.environ:
    g_milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
  if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
    g_milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
  if 'MILTER_DKIM_ENABLED' in os.environ:
    g_milter_dkim_enabled = True
    logging.info("DKIM signature authorisation enabled")
    if 'MILTER_DKIM_AUTHSERVID' in os.environ:
      g_milter_dkim_authservid = os.environ['MILTER_DKIM_AUTHSERVID'].lower()
      logging.info("DKIM AuthServID: " + g_milter_dkim_authservid)
    else:
      logging.error("ENV[MILTER_DKIM_AUTHSERVID] is mandatory!")
      sys.exit(1)
  if 'MILTER_POLICY_SOURCE' in os.environ:
    g_milter_policy_source = os.environ['MILTER_POLICY_SOURCE']
  if g_milter_policy_source == 'file':
    if 'MILTER_POLICY_FILE' in os.environ:
      g_milter_policy_file = os.environ['MILTER_POLICY_FILE']
      try:
        g_milter_policy_backend = ExOTAPolicyBackendJSON(g_milter_policy_file)
        logging.info("JSON policy backend initialized")
      except ExOTAPolicyException as e:
        logging.error("Policy backend error: {0}".format(e.message))
        sys.exit(1)
    else:
      logging.error("ENV[MILTER_POLICY_FILE] is mandatory!")
      sys.exit(1)
  try:
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = ExOTAMilter
    # Tell the MTA which features we use
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)
    logging.info("Startup " + g_milter_name +
      "@socket: " + g_milter_socket
    )
    Milter.runmilter(g_milter_name,g_milter_socket,timeout,True)
    logging.info("Shutdown " + g_milter_name)
  except:
    logging.error("MAIN-EXCEPTION: " + traceback.format_exc())