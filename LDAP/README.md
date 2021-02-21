# ExOTA-Milter with LDAP policy backend
For small setups, with not so many domains, the JSON-file policy backend (default) may be sufficient. If you´re an email service provider (ESP), maintaining a lot of customer domains in a LDAP server, you may want use the LDAP backend instead.

### Configuration
To enable LDAP backend support you need to set up the following environment variables:
```
export MILTER_POLICY_SOURCE=ldap
export MILTER_LDAP_SERVER_URI=ldaps://your.ldap.server
export MILTER_LDAP_SEARCH_BASE=ou=your-customer-domains,dc=example,dc=org
export MILTER_LDAP_QUERY='(domainNameAttr=%d)'
export MILTER_LDAP_BINDDN=uid=exota-milter,ou=apps,dc=example,dc=org
export MILTER_LDAP_BINDPW='$uPer§ecRet1!'
```
The `MILTER_LDAP_QUERY` variable requires a macro/placeholder **%d**, which identifies the domain name to search for in the LDAP tree.

### Use EXoTA-Milter LDAP schema
If you´re willing to use the ExOTA-Milter LDAP schema, you don´t need further configuration. Just feed your LDAP-server with the [ready to use schema file](exota-milter.schema) (auxiliary objectclass) and extend your customers domain objects with the following objectclass and attributes:

Objectclass: `exotaMilterPolicy`  
Attributes:
* exotaMilterTenantId
* exotaMilterDkimEnabled
* exotaMilterDkimAlignmentRequired

### Use your custom LDAP schema
If you want to use an own custom LDAP schema with ExOTA-Milter you will have to set up the following environment variables as well:
```
export MILTER_LDAP_TENANT_ID_ATTR=your_custom_tenant_id_attr
export MILTER_LDAP_DKIM_ENABLED_ATTR=your_custom_dkim_enabled_attr
export MILTER_LDAP_DKIM_ALIGNMENT_REQUIRED_ATTR=your_custom_dkim_alignment_required_attr
```
Please make sure that your custom LDAP attributes are set up accordingly the **ExOTA-Milter** [LDAP schema](exota-milter.schema), otherwise your setup will not work as expected!