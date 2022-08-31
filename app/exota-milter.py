import Milter
import sys
import traceback
import os
import string
import random
import re
import email.utils
import authres
from policy import (
  ExOTAPolicyException, ExOTAPolicyNotFoundException, 
  ExOTAPolicyBackendJSON, ExOTAPolicyBackendLDAP, 
  ExOTAPolicyInvalidException, ExOTAPolicyBackendException
)
from logger import (
  init_logger, log_info, log_error, log_debug
)

# Globals with defaults. Can/should be modified by ENV-variables on startup.
# ENV[MILTER_NAME]
g_milter_name = 'exota-milter'
# ENV[MILTER_SOCKET]
g_milter_socket = '/socket/' + g_milter_name
# ENV[MILTER_REJECT_MESSAGE]
g_milter_reject_message = 'Security policy violation!'
# ENV[MILTER_TMPFAIL_MESSAGE]
g_milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
# ENV[MILTER_TENANT_ID_REQUIRED]
g_milter_tenant_id_required = False
# ENV[MILTER_DKIM_ENABLED]
g_milter_dkim_enabled = False
# ENV[MILTER_DKIM_ALIGNMENT_REQUIRED]
g_milter_dkim_alignment_required = False
# ENV[MILTER_TRUSTED_AUTHSERVID]
g_milter_trusted_authservid = 'invalid'
# ENV[MILTER_POLICY_SOURCE]
g_milter_policy_source = 'file'
# ENV[MILTER_POLICY_FILE]
g_milter_policy_file = '/data/policy.json'
# ENV[MILTER_X509_ENABLED]
g_milter_x509_enabled = False
# ENV[MILTER_X509_TRUSTED_CN]
g_milter_x509_trusted_cn = 'mail.protection.outlook.com'
# ENV[MILTER_X509_IP_WHITELIST]
g_milter_x509_ip_whitelist = ['127.0.0.1','::1']
# ENV[MILTER_ADD_HEADER]
g_milter_add_header = False
# ENV[MILTER_AUTHSERVID]
g_milter_authservid = None
# ENV[MILTER_LDAP_SERVER_URI]
g_milter_ldap_server_uri = ''
# ENV[MILTER_LDAP_RECEIVE_TIMEOUT]
g_milter_ldap_receive_timeout = 5
# ENV[MILTER_LDAP_BINDDN]
g_milter_ldap_binddn = ''
# ENV[MILTER_LDAP_BINDPW]
g_milter_ldap_bindpw = ''
# ENV[MILTER_LDAP_SEARCH_BASE]
g_milter_ldap_search_base = ''
# ENV[MILTER_LDAP_QUERY]
g_milter_ldap_query = ''
# ENV[MILTER_LDAP_TENANT_ID_ATTR]
g_milter_ldap_tenant_id_attr = 'exotaMilterTenantId'
# ENV[MILTER_LDAP_DKIM_ENABLED_ATTR]
g_milter_ldap_dkim_enabled_attr = 'exotaMilterDkimEnabled'
# ENV[MILTER_LDAP_DKIM_ALIGNMENT_REQIRED_ATTR]
g_milter_ldap_dkim_alignment_required_attr = 'exotaMilterDkimAlignmentRequired'

# Another globals
g_policy_backend = None
g_re_domain = re.compile(r'^.*@(\S+)$', re.IGNORECASE)
g_milter_ldap_conn = None

class ExOTAMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.x509_client_valid = False
    self.client_ip = None
    self.client_port = None
    self.reset()
    log_debug(self.mconn_id + " INIT: {0}".format(self.__dict__))

  def reset(self):
    self.hdr_from = None
    self.hdr_from_domain = None
    self.hdr_resent_from = None
    self.hdr_resent_from_domain = None
    self.forwarded = False
    self.hdr_tenant_id = None
    self.hdr_tenant_id_count = 0
    self.hdr_different_tenant_id = False
    self.x509_whitelisted = False
    self.dkim_valid = False
    self.passed_dkim_results = []
    self.dkim_aligned = False
    self.xar_hdr_count = 0
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )
    log_debug(self.mconn_id + " reset(): {0}".format(self.__dict__))

  def smfir_reject(self, **kwargs):
    message = g_milter_reject_message
    if 'message' in kwargs:
      message = kwargs['message']
    if 'queue_id' in kwargs:
      message = "queue_id: {0} - {1}".format(kwargs['queue_id'], message)
    if 'reason' in kwargs:
      message = "{0} - reason: {1}".format(message, kwargs['reason'])
    log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
      ": milter_action=reject message={0}".format(message)
    )
    self.reset()
    self.setreply('550','5.7.1', message)
    return Milter.REJECT
  
  def smfir_tempfail(self, **kwargs):
    message = g_milter_tmpfail_message
    if 'message' in kwargs:
      message = kwargs['message']
    if 'queue_id' in kwargs:
      message = "queue_id: {0} - {1}".format(kwargs['queue_id'], message)
    if 'reason' in kwargs:
      message = "{0} - reason: {1}".format(message, kwargs['reason'])
    log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
      ": milter_action=tempfail message={0}".format(message)
    )
    self.reset()
    self.setreply('450','4.7.1', message)
    return Milter.TEMPFAIL
  
  def smfir_continue(self):
    return Milter.CONTINUE

  # Not registered/used callbacks
  @Milter.nocallback
  def hello(self, heloname):
    return self.smfir_continue()
  @Milter.nocallback
  def eoh(self):
    return self.smfir_continue()
  @Milter.nocallback
  def body(self, chunk):
    return self.smfir_continue()

  def connect(self, IPname, family, hostaddr):
    self.reset()
    self.client_ip = hostaddr[0]
    self.client_port = hostaddr[1]
    log_debug(self.mconn_id + "/CONNECT client_ip={0} client_port={1}".format(
      self.client_ip, self.client_port
    ))
    return self.smfir_continue()

  # Mandatory callback
  def envfrom(self, mailfrom, *str):
    log_debug(self.mconn_id + "/FROM 5321.from={0}".format(mailfrom))
    log_debug(self.mconn_id + "/FROM {0}".format(self.__dict__))
    return self.smfir_continue()

  # Mandatory callback
  def envrcpt(self, to, *str):
    log_debug(self.mconn_id + "/RCPT 5321.rcpt={0}".format(to))
    return self.smfir_continue()

  def header(self, name, hval):
    log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
      "/HDR: Header: {0}, Value: {1}".format(name, hval)
    )

    # Parse RFC-5322-From header
    if(name.lower() == "From".lower()):
      hdr_5322_from = email.utils.parseaddr(hval)
      self.hdr_from = hdr_5322_from[1].lower()
      m = re.match(g_re_domain, self.hdr_from)
      if m is None:
        log_error(self.mconn_id  + "/" + str(self.getsymval('i')) + "/HDR " +
          "Could not determine domain-part of 5322.from=" + self.hdr_from
        )
        return self.smfir_reject(queue_id=self.getsymval('i'))
      self.hdr_from_domain = m.group(1)
      log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/HDR: 5322.from={0}, 5322.from_domain={1}".format(
          self.hdr_from, self.hdr_from_domain
        )
      )
    
    # Parse RFC-5322-Resent-From header (Forwarded)
    if(name.lower() == "Resent-From".lower()):
      hdr_5322_resent_from = email.utils.parseaddr(hval)
      self.hdr_resent_from = hdr_5322_resent_from[1].lower()
      m = re.match(g_re_domain, self.hdr_resent_from)
      if m is None:
        log_error(self.mconn_id  + "/" + str(self.getsymval('i')) + "/HDR " +
          "Could not determine domain-part of 5322.resent_from=" + self.hdr_resent_from
        )
      else:
        self.hdr_resent_from_domain = m.group(1).lower()
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/HDR: 5322.resentfrom={0}, 5322.resent_from_domain={1}".format(
            self.hdr_resent_from, self.hdr_resent_from_domain
          )
        )
    
    # Parse non-standardized X-MS-Exchange-CrossTenant-Id header
    elif(name.lower() == "X-MS-Exchange-CrossTenant-Id".lower()):
      if g_milter_tenant_id_required == True:
        log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/HDR: Tenant-ID: {0}".format(hval.lower())
          )
        if self.hdr_tenant_id_count > 0:
          if not self.hdr_tenant_id == hval.lower():
            self.hdr_different_tenant_id = True
            log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
              "/HDR: Different Tenant-IDs found!"
            )
        else:
          self.hdr_tenant_id_count += 1
          self.hdr_tenant_id = hval.lower()

    # Parse RFC-7601 Authentication-Results header
    elif(name.lower() == "Authentication-Results".lower()):
      if g_milter_dkim_enabled == True:
        ar = None
        try:
          ar = authres.AuthenticationResultsHeader.parse(
            "{0}: {1}".format(name, hval)
          )
          if ar.authserv_id == g_milter_trusted_authservid:
            for ar_result in ar.results:
              if ar_result.method == 'dkim':
                if ar_result.result == 'pass':
                  self.passed_dkim_results.append({
                    "sdid": ar_result.header_d.lower()
                  })
                  log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
                    "/HDR: DKIM passed SDID {0}".format(ar_result.header_d)
                  )
                  self.dkim_valid = True
          else:
            log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
              "/HDR: Ignoring authentication results of {0}".format(ar.authserv_id)
            )
        except Exception as e:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/HDR: AR-parse exception: {0}".format(str(e))
          )
    
    elif(name == "X-ExOTA-Authentication-Results"):
      log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/HDR: Found X-ExOTA-Authentication-Results header. Marking for deletion."
      )
      self.xar_hdr_count += 1

    return self.smfir_continue()

  # EOM is mandatory as well and thus always called by MTA
  def eom(self):
    # Here in EoM the final policy logic happens.

    # Check if client certificate CN matches trusted CN
    if g_milter_x509_enabled:
      for whitelisted_client_ip in g_milter_x509_ip_whitelist:
        if self.client_ip == whitelisted_client_ip:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) 
            + "/EOM: x509 CN check: client-IP '{0}' is whitelisted".format(
              whitelisted_client_ip
            )
          )
          self.x509_whitelisted = True
      if not self.x509_whitelisted:
        cert_subject = self.getsymval('{cert_subject}') 
        if cert_subject is None:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) 
            + "/EOM: No trusted x509 client CN found - action=reject"
          )
          return self.smfir_reject(
            queue_id = self.getsymval('i'),
            reason = 'No trusted x509 client CN found'
          )
        else:
          if g_milter_x509_trusted_cn.lower() == cert_subject.lower():
            self.x509_client_valid = True
            log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
              "/EOM: Trusted x509 client CN {0}".format(cert_subject)
            )
          else:
            log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
              "/EOM: Untrusted x509 client CN {0} - action=reject".format(cert_subject)
            )
            return self.smfir_reject(
              queue_id = self.getsymval('i'),
              reason = "Untrusted x509 client CN: {0}".format(cert_subject)
            )

    if self.hdr_from is None:
      log_error(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: exception: could not determine 5322.from header - action=reject"
      )
      return self.smfir_reject(
        queue_id = self.getsymval('i'),
        reason = '5322.from header missing'
      )

    if g_milter_tenant_id_required == True:
      if self.hdr_different_tenant_id == True:
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: Multiple/different tenant-ID headers found for {0} - action=reject".format(
            self.hdr_from_domain
          )
        )
        return self.smfir_reject(
          queue_id = self.getsymval('i'),
          reason = 'Multiple/different tenant-ID headers found!'
        )

    # Get policy for 5322.from_domain
    policy = None
    try:
      policy = g_policy_backend.get(self.hdr_from_domain)
      log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: Policy for 5322.from_domain={0} fetched from backend: *{1}*".format(
          self.hdr_from_domain, str(policy)
        )
      )
    except ExOTAPolicyBackendException as e:
      log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: Policy backend problem: {0}".format(e.message)
      )
      return self.smfir_tempfail(
        queue_id = self.getsymval('i'),
        reason = "Policy backend problem"
      )
    except ExOTAPolicyInvalidException as e:
      log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: Invalid policy for 5322.from_domain={0}: {1}".format(
          self.hdr_from_domain, e.message
        )
      )
      return self.smfir_reject(
        queue_id = self.getsymval('i'),
        reason = "Invalid policy for 5322.from_domain {0}".format(
          self.hdr_from_domain
        )
      )
    except (ExOTAPolicyException, ExOTAPolicyNotFoundException) as e:
      log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: 5322.from: {0}".format(e.message)
      )
      # Forwarded message? Maybe the Resent-From header domain matches.
      if self.hdr_resent_from_domain is not None:
        try:
          policy = g_policy_backend.get(self.hdr_resent_from_domain)
          log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/EOM: Policy for 5322.resent_from_domain={0} fetched from backend: *{1}*".format(
              self.hdr_resent_from_domain, str(policy)
            )
          )
          self.forwarded = True
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/EOM: Forwarded message -> Policy for 5322.resent_from_domain={0} found.".format(
              self.hdr_resent_from_domain
            )
          )
        except ExOTAPolicyBackendException as e:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/EOM: Policy backend problem: {0}".format(e.message)
          )
          return self.smfir_tempfail(
            queue_id = self.getsymval('i'),
            reason = "Policy backend problem"
          )
        except ExOTAPolicyInvalidException as e:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/EOM: Invalid policy for 5322.resent_from_domain={0}: {1}".format(
              self.hdr_resent_from_domain, e.message
            )
          )
          return self.smfir_reject(
            queue_id = self.getsymval('i'),
            reason = "Invalid policy for 5322.resent_from_domain {0}".format(
              self.hdr_resent_from_domain
            )
          )
        except (ExOTAPolicyException, ExOTAPolicyNotFoundException) as e:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/EOM: 5322.resent-from: {0}".format(e.message)
          )
          return self.smfir_reject(
            queue_id = self.getsymval('i'),
            reason = "No policy for 5322.resent_from_domain {0}".format(
              self.hdr_resent_from_domain
            )
          ) 
      else:
        return self.smfir_reject(
          queue_id = self.getsymval('i'),
          reason = "No policy for 5322.from_domain {0}".format(self.hdr_from_domain)
        )

    if g_milter_tenant_id_required == True:
      if self.hdr_tenant_id is None:
        log_error(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: exception: could not determine X-MS-Exchange-CrossTenant-Id - action=reject"
        )
        return self.smfir_reject(
          queue_id = self.getsymval('i'),
          reason = 'Tenant-ID is missing!'
        )
      if self.hdr_tenant_id == policy.get_tenant_id():
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: tenant_id={0} status=match".format(self.hdr_tenant_id)
        )
      else:
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: tenant_id={0} status=no_match - action=reject".format(
            self.hdr_tenant_id
          )
        )
        return self.smfir_reject(
          queue_id = self.getsymval('i'),
          reason = 'No policy match for tenant-id'
        )

    if g_milter_dkim_enabled and policy.is_dkim_enabled():
      log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: 5322.from_domain={0} dkim_auth=enabled".format(self.hdr_from_domain)
      )
      if self.dkim_valid:
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: Valid DKIM signatures found"
        )
        for passed_dkim_result in self.passed_dkim_results:
          if self.hdr_from_domain == passed_dkim_result['sdid']:
            log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
              "/EOM: Found aligned DKIM signature for SDID: {0}".format(
                passed_dkim_result['sdid']
              ) 
            )
            self.dkim_aligned = True
        if not self.dkim_aligned:
          log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
            "/EOM: No aligned DKIM signatures found!"
          )
          if g_milter_dkim_alignment_required:
            if policy.is_dkim_alignment_required() == False:
              log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
                "/EOM: Policy overrides DKIM alignment requirement to '{0}'!".format(
                  policy.is_dkim_alignment_required()
                )
              )
            else:
              return self.smfir_reject(
                queue_id = self.getsymval('i'),
                reason = 'DKIM alignment required!'
              )
      else:
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: No valid DKIM authentication result found"
        )
        return self.smfir_reject(
          queue_id = self.getsymval('i'),
          reason = 'No valid DKIM authentication results found'
        )
    
    # Delete all existing X-ExOTA-Authentication-Results headers
    for i in range(self.xar_hdr_count, 0, -1):
      log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: Deleting X-ExOTA-Authentication-Results header"
      )
      try:
        self.chgheader("X-ExOTA-Authentication-Results", i-1, '')
      except Exception as e:
        log_error(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: Deleting X-ExOTA-Authentication-Results failed: {0}".format(str(e))
        )

    if g_milter_add_header:
      try:
        addhdr_value = str(
          "{0};\n" + 
          "  auth=pass 5322_from_domain={1} dkim={2} dkim_aligned={3} " + 
          "x509_client_trust={4} forwarded={5}"
        ).format(
          g_milter_authservid, self.hdr_from_domain, policy.is_dkim_enabled(),
          self.dkim_aligned, g_milter_x509_enabled, self.forwarded
        )
        log_debug(addhdr_value)
        self.addheader("X-ExOTA-Authentication-Results", addhdr_value)
        log_debug(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: AR-header added"
        )
      except Exception as e:
        log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
          "/EOM: addheader(AR) failed: {0}".format(str(e))
        )

    if g_milter_dkim_enabled:
      log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: Tenant successfully authorized (dkim_enabled={0} dkim_aligned={1})".format(
          policy.is_dkim_enabled(), self.dkim_aligned
        )
      )
    else:
      log_info(self.mconn_id + "/" + str(self.getsymval('i')) +
        "/EOM: Tenant successfully authorized"
      )
    self.reset()
    return self.smfir_continue()

  def abort(self):
    # Client disconnected prematurely
    log_debug(self.mconn_id + "/ABORT")
    return self.smfir_continue()

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    log_debug(self.mconn_id + "/CLOSE {0}".format(self.__dict__))
    return self.smfir_continue()

if __name__ == "__main__":
  init_logger()
  if 'MILTER_NAME' in os.environ:
    g_milter_name = os.environ['MILTER_NAME']
  log_info("ENV[MILTER_NAME]: {0}".format(g_milter_name))
  if 'MILTER_SOCKET' in os.environ:
    g_milter_socket = os.environ['MILTER_SOCKET']
  log_info("ENV[MILTER_SOCKET]: {0}".format(g_milter_socket))
  if 'MILTER_REJECT_MESSAGE' in os.environ:
    g_milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
  log_info("ENV[MILTER_REJECT_MESSAGE]: {0}".format(g_milter_reject_message))
  if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
    g_milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
  log_info("ENV[MILTER_TMPFAIL_MESSAGE]: {0}".format(g_milter_tmpfail_message))
  if 'MILTER_TENANT_ID_REQUIRED' in os.environ:
    g_milter_tenant_id_required = True
  log_info("ENV[MILTER_TENANT_ID_REQUIRED]: {0}".format(g_milter_tenant_id_required))
  if 'MILTER_DKIM_ENABLED' in os.environ:
    g_milter_dkim_enabled = True
    if 'MILTER_TRUSTED_AUTHSERVID' in os.environ:
      g_milter_trusted_authservid = os.environ['MILTER_TRUSTED_AUTHSERVID'].lower()
      log_info("ENV[MILTER_TRUSTED_AUTHSERVID]: {0}".format(g_milter_trusted_authservid))
    else:
      log_error("ENV[MILTER_TRUSTED_AUTHSERVID] is mandatory!")
      sys.exit(1)
    if 'MILTER_DKIM_ALIGNMENT_REQUIRED' in os.environ:
      if os.environ['MILTER_DKIM_ALIGNMENT_REQUIRED'] == 'True':
        g_milter_dkim_alignment_required = True
      elif os.environ['MILTER_DKIM_ALIGNMENT_REQUIRED'] == 'False':
        g_milter_dkim_alignment_required = False
      else:
        log_error("ENV[MILTER_DKIM_ALIGNMENT_REQUIRED] must be a boolean type: 'True' or 'False'!")
        sys.exit(1)
    log_info("ENV[MILTER_DKIM_ALIGNMENT_REQUIRED]: {0}".format(
      g_milter_dkim_alignment_required
    ))
  log_info("ENV[MILTER_DKIM_ENABLED]: {0}".format(g_milter_dkim_enabled))
  if 'MILTER_X509_ENABLED' in os.environ:
    g_milter_x509_enabled = True
    if 'MILTER_X509_TRUSTED_CN' in os.environ:
      g_milter_x509_trusted_cn = os.environ['MILTER_X509_TRUSTED_CN']
    log_info("ENV[MILTER_X509_TRUSTED_CN]: {0}".format(g_milter_x509_trusted_cn))
    if 'MILTER_X509_IP_WHITELIST' in os.environ:
      g_milter_x509_ip_whitelist = "".join(os.environ['MILTER_X509_IP_WHITELIST'].split())
      g_milter_x509_ip_whitelist = g_milter_x509_ip_whitelist.split(',')
    log_info("ENV[MILTER_X509_IP_WHITELIST]: {0}".format(g_milter_x509_ip_whitelist))
  log_info("ENV[MILTER_X509_ENABLED]: {0}".format(g_milter_x509_enabled))
  if 'MILTER_ADD_HEADER' in os.environ:
    g_milter_add_header = True
    if 'MILTER_AUTHSERVID' in os.environ:
      g_milter_authservid = os.environ['MILTER_AUTHSERVID']
      if not re.match(r'^\S+$', g_milter_authservid):
        log_error("ENV[MILTER_AUTHSERVID] is invalid: {0}".format(g_milter_authservid))
      log_info("ENV[MILTER_AUTHSERVID]: {0}".format(g_milter_authservid))
    else:
      log_error("ENV[MILTER_AUTHSERVID] is mandatory!")
      sys.exit(1)
  log_info("ENV[MILTER_ADD_HEADER]: {0}".format(g_milter_add_header))
  if 'MILTER_POLICY_SOURCE' in os.environ:
    g_milter_policy_source = os.environ['MILTER_POLICY_SOURCE']
  log_info("ENV[MILTER_POLICY_SOURCE]: {0}".format(g_milter_policy_source))
  if g_milter_policy_source == 'file':
    if 'MILTER_POLICY_FILE' in os.environ:
      g_milter_policy_file = os.environ['MILTER_POLICY_FILE']
      log_info("ENV[MILTER_POLICY_FILE]: {0}".format(g_milter_policy_file))
      try:
        g_policy_backend = ExOTAPolicyBackendJSON(g_milter_policy_file)
        log_info("JSON policy backend initialized")
      except ExOTAPolicyException as e:
        log_error("Policy backend error: {0}".format(e.message))
        sys.exit(1)
    else:
      log_error("ENV[MILTER_POLICY_FILE] is mandatory!")
      sys.exit(1)
  elif g_milter_policy_source == 'ldap':
    if 'MILTER_LDAP_SERVER_URI' not in os.environ:
      log_error("ENV[MILTER_LDAP_SERVER_URI] is mandatory!")
      sys.exit(1)
    g_milter_ldap_server_uri = os.environ['MILTER_LDAP_SERVER_URI']
    if 'MILTER_LDAP_RECEIVE_TIMEOUT' in os.environ:
      try:
        g_milter_ldap_receive_timeout = int(os.environ['MILTER_LDAP_RECEIVE_TIMEOUT'])
      except ValueError:
        log_error("ENV[MILTER_LDAP_RECEIVE_TIMEOUT] must be an integer!")
        sys.exit(1)  
    log_info("ENV[MILTER_LDAP_RECEIVE_TIMEOUT]: {0}".format(
      g_milter_ldap_receive_timeout
    ))
    if 'MILTER_LDAP_BINDDN' not in os.environ:
      log_info("ENV[MILTER_LDAP_BINDDN] not set! Continue...")
    else:
      g_milter_ldap_binddn = os.environ['MILTER_LDAP_BINDDN']
    if 'MILTER_LDAP_BINDPW' not in os.environ:
      log_info("ENV[MILTER_LDAP_BINDPW] not set! Continue...")
    else:
      g_milter_ldap_bindpw = os.environ['MILTER_LDAP_BINDPW']
    if 'MILTER_LDAP_SEARCH_BASE' not in os.environ:
      log_error("ENV[MILTER_LDAP_SEARCH_BASE] is mandatory!")
      sys.exit(1)
    g_milter_ldap_search_base = os.environ['MILTER_LDAP_SEARCH_BASE']
    if 'MILTER_LDAP_QUERY' not in os.environ:
      log_error("ENV[MILTER_LDAP_QUERY] is mandatory!")
      sys.exit(1)
    g_milter_ldap_query = os.environ['MILTER_LDAP_QUERY']
    if 'MILTER_LDAP_TENANT_ID_ATTR' in os.environ:
      g_milter_ldap_tenant_id_attr = os.environ['MILTER_LDAP_TENANT_ID_ATTR']
    if 'MILTER_LDAP_DKIM_ENABLED_ATTR' in os.environ:
      g_milter_ldap_dkim_enabled_attr = os.environ['MILTER_LDAP_DKIM_ENABLED_ATTR']
    if 'MILTER_LDAP_DKIM_ALIGNMENT_REQUIRED_ATTR' in os.environ:
      g_milter_ldap_dkim_alignment_required_attr = os.environ['MILTER_LDAP_DKIM_ALIGNMENT_REQUIRED_ATTR']
    try:
      ldap_config = {
        'ldap_server_uri': g_milter_ldap_server_uri,
        'ldap_binddn': g_milter_ldap_binddn,
        'ldap_bindpw': g_milter_ldap_bindpw,
        'ldap_receive_timeout': g_milter_ldap_receive_timeout,
        'ldap_search_base': g_milter_ldap_search_base,
        'ldap_query': g_milter_ldap_query,
        'ldap_tenant_id_attr': g_milter_ldap_tenant_id_attr,
        'ldap_dkim_enabled_attr': g_milter_ldap_dkim_enabled_attr,
        'ldap_dkim_alignment_required_attr': g_milter_ldap_dkim_alignment_required_attr
      }
      g_policy_backend = ExOTAPolicyBackendLDAP(ldap_config)
      log_info("LDAP policy backend initialized")
    except ExOTAPolicyException as e:
      log_error("Policy backend error: {0}".format(e.message))
      sys.exit(1)
  else:
    log_debug("Unsupported backend: {0}!".format(g_milter_policy_source))
    sys.exit(1)
  try:
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = ExOTAMilter
    Milter.set_flags(Milter.ADDHDRS + Milter.CHGHDRS)
    log_info("Startup " + g_milter_name +
      "@socket: " + g_milter_socket
    )
    Milter.runmilter(g_milter_name,g_milter_socket,timeout,True)
    log_info("Shutdown " + g_milter_name)
  except:
    log_error("MAIN-EXCEPTION: " + traceback.format_exc())
    sys.exit(1)