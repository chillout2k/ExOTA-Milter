import json
import traceback
import re

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
    self.dkim_enabled = policy_dict['dkim_enabled']

  def get_tenant_id(self):
    return self.tenant_id

  def is_dkim_enabled(self):
    return self.dkim_enabled

  @staticmethod
  def check_policy(policy_dict):
    if 'tenant_id' not in policy_dict:
      raise ExOTAPolicyInvalidException(
        "Policy must have a 'tenant_id' attribute!"
      )
    else:
      if policy_dict['tenant_id'] == '':
        raise ExOTAPolicyInvalidException(
          "'tenant_id' must not be empty!"
        )
      if re.match(r'^.*\s+.*$', policy_dict['tenant_id']):
        raise ExOTAPolicyInvalidException(
          "'tenant_id' must not contain whitespace characters!"
        )
    if 'dkim_enabled' not in policy_dict:
      raise ExOTAPolicyInvalidException(
        "Policy must have a 'dkim_enabled' attribute!"
      )
    else:
      if not isinstance(policy_dict['dkim_enabled'], bool):
        raise ExOTAPolicyInvalidException(
          "'dkim_enabled'({0}) must be boolean!".format(policy_dict['dkim_enabled'])
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
        "Policy for from_domain={0} not found".format(from_domain)
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