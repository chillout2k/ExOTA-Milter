import json
import traceback
import re
from uuid import UUID

class ExOTAPolicyException(Exception):
  def __init__(self, message):
    self.message = message

class ExOTAPolicyNotFoundException(ExOTAPolicyException):
  pass

class ExOTAPolicyInvalidException(ExOTAPolicyException):
  pass

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
      raise ExOTAPolicyException(
        "JSON-error in policy file: " + str(e)
      ) from e
    except Exception as e:
      raise ExOTAPolicyException(
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
class ExOTAPolicyBackendLDAP(ExOTAPolicyBackendJSON):
  type = 'ldap'
  pass