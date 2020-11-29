# prepare testing env
```
export LOG_LEVEL=debug
export MILTER_SOCKET=/tmp/exota-milter
export MILTER_POLICY_FILE=tests/policy.json
export MILTER_DKIM_ENABLED=yepp
export MILTER_TRUSTED_AUTHSERVID=my-auth-serv-id
export MILTER_X509_ENABLED=yepp
export MILTER_X509_TRUSTED_CN=mail.protection.outlook.com
```

# start milter
`python3 app/exota-milter.py`

# execute `miltertest`
First of all install the `miltertest` binary. Under debian based distros 
it´s located in the `opendkim-tools` package.

`miltertest -v -D socket="${MILTER_SOCKET}" -s tests/miltertest.lua`