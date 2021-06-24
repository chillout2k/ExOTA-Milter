import json
import traceback
import re
from uuid import UUID
from ldap3.core.exceptions import LDAPException

class ExOTAPolicyException(Exception):
  def __init__(self, message):
    self.message = message

class ExOTAPolicyNotFoundException(ExOTAPolicyException):
  pass

class ExOTAPolicyInvalidException(ExOTAPolicyException):
  pass

class ExOTAPolicyBackendException(Exception):
  def __init__(self, message):
    self.message = message

class ExOTAPolicy():
  def __init__(self, policy_dict):
    self.tenant_id = policy_dict['tenant_id']
    if 'dkim_enabled' in policy_dict:
      self.dkim_enabled = policy_dict['dkim_enabled']
    else:
      self.dkim_enabled = True
    if 'dkim_alignment_required' in policy_dict:
      self.dkim_alignment_required = policy_dict['dkim_alignment_required']
    else:
      # DKIM alignment per policy enabled by default
      self.dkim_alignment_required = True
  
  def __str__(self):
    return "Tenant-ID={0}, DKIM={1}, DKIM-alignment-required={2}". format(
      self.tenant_id, self.dkim_enabled, self.dkim_alignment_required 
    )

  def get_tenant_id(self):
    return self.tenant_id

  def is_dkim_enabled(self):
    return self.dkim_enabled

  def is_dkim_alignment_required(self):
    return self.dkim_alignment_required

  @staticmethod
  def check_policy(policy_dict):
    if 'tenant_id' not in policy_dict:
      raise ExOTAPolicyInvalidException(
        "Policy must have a 'tenant_id' key!"
      )
    if policy_dict['tenant_id'] is None:
      raise ExOTAPolicyInvalidException(
        "'tenant_id' needs a value!"
      )
    for policy_key in policy_dict:
      if policy_key == 'tenant_id':
        try:
          UUID(policy_dict[policy_key])
        except ValueError as e:
          raise ExOTAPolicyInvalidException(
            "Invalid 'tenant_id': {0}".format(str(e))
          ) from e
        except Exception as e:
          raise ExOTAPolicyInvalidException(
            "Invalid 'tenant_id': {0}".format(traceback.format_exc())
          ) from e
      elif policy_key == 'dkim_enabled':
        if not isinstance(policy_dict[policy_key], bool):
          raise ExOTAPolicyInvalidException(
            "'dkim_enabled'({0}) must be boolean!".format(policy_dict['dkim_enabled'])
          )
      elif policy_key == 'dkim_alignment_required':
        if not isinstance(policy_dict[policy_key], bool):
          raise ExOTAPolicyInvalidException(
            "'dkim_alignment_required'({0}) must be boolean!".format(
              policy_dict[policy_key]
            )
          )
      else:
        raise ExOTAPolicyInvalidException(
          "Invalid policy_key '{0}'!".format(policy_key)
        )

class ExOTAPolicyBackend():
  type = None
  def __init__(self):
    pass
  def get(self, from_domain):
    pass

########## JSON file
class ExOTAPolicyBackendJSON(ExOTAPolicyBackend):
  type = 'json'
  def __init__(self, file_path):
    self.policies = None
    try:
      with open(file_path, 'r') as policy_file:
        self.policies = json.load(policy_file)
        policy_file.close()
        # validate policy
        for policy in self.policies:
          try:
            ExOTAPolicy.check_policy(self.policies[policy])
          except ExOTAPolicyInvalidException as e:
            raise ExOTAPolicyException(
              "Policy {0} is invalid: {1}".format(policy, e.message)
            ) from e
    except json.decoder.JSONDecodeError as e:
      raise ExOTAPolicyBackendException(
        "JSON-error in policy file: " + str(e)
      ) from e
    except Exception as e:
      raise ExOTAPolicyBackendException(
        "Error reading policy file: " + traceback.format_exc()
      ) from e
  
  def get(self, from_domain):
    try:
      return ExOTAPolicy(self.policies[from_domain])
    except KeyError as e:
      raise ExOTAPolicyNotFoundException(
        "Policy for domain={0} not found".format(from_domain)
      ) from e
    except Exception as e:
      raise ExOTAPolicyException(
        "Error fetching policy for {0}: {1}".format(
          from_domain, traceback.format_exc()
        )
      ) from e

########## LDAP
class ExOTAPolicyBackendLDAP(ExOTAPolicyBackend):
  type = 'ldap'
  def __init__(self, ldap_config):
    try:
      self.conn = ldap_config['ldap_conn']
      self.search_base = ldap_config['ldap_search_base']
      self.query = ldap_config['ldap_query']
      self.tenant_id_attr = ldap_config['ldap_tenant_id_attr']
      self.dkim_enabled_attr = ldap_config['ldap_dkim_enabled_attr']
      self.dkim_alignment_required_attr = ldap_config['ldap_dkim_alignment_required_attr']
    except Exception as e:
      raise ExOTAPolicyBackendException(
        "An error occured while initializing LDAP backend: " + traceback.format_exc()
      ) from e

  def get(self, from_domain):
    self.query = self.query.replace('%d', from_domain)
    try:
      self.conn.search(
        self.search_base,
        self.query,
        attributes=[
          self.tenant_id_attr,
          self.dkim_enabled_attr,
          self.dkim_alignment_required_attr
        ]
      )
      if len(self.conn.entries) == 1:
        entry = self.conn.entries[0]
        policy_dict = {}
        if self.tenant_id_attr in entry:
          policy_dict['tenant_id'] = entry[self.tenant_id_attr].value
        if self.dkim_enabled_attr in entry:
          if entry[self.dkim_enabled_attr].value == 'TRUE':
            policy_dict['dkim_enabled'] = True
          else:
            policy_dict['dkim_enabled'] = False
        if self.dkim_alignment_required_attr in entry:
          if entry[self.dkim_alignment_required_attr].value == 'TRUE':
            policy_dict['dkim_alignment_required'] = True
          else:
            policy_dict['dkim_alignment_required'] = False
        ExOTAPolicy.check_policy(policy_dict)
        return ExOTAPolicy(policy_dict)
      elif len(self.conn.entries) > 1:
        raise ExOTAPolicyInvalidException(
          "Multiple policies found for domain={0}!".format(from_domain)
        )
      else:
        raise ExOTAPolicyNotFoundException(
          "Policy for domain={0} not found".format(from_domain)
        )
    except LDAPException as e:
      raise ExOTAPolicyBackendException(e) from e