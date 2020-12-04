# Prepare testing env
First of all, please configure a python virtual environment and install all necessary python packages listed under `requirements.txt`. Go to the root-directory of this repo and
1. `python3 -m venv venv`
1. `. venv/bin/activate`
1. `pip3 install -r requirements.txt`

It´s not realy neccessary to configure a fully functional milter-aware MTA to see **ExOTA-Milter** in action. All you need is 
* a binary called `miltertest`. Under debian based distros it´s located in the `opendkim-tools` package.
* a lua-script for miltertest: `tests/miltertest.lua`
* an **ExOTA-Milter** policy JSON-file: `tests/policy.json`

Except for the `miltertest` binary you´ll find all mandatory resources to run a test in this repo.

```
export LOG_LEVEL=debug
export MILTER_SOCKET=/tmp/exota-milter
export MILTER_POLICY_FILE=tests/policy.json
export MILTER_DKIM_ENABLED=yepp
export MILTER_TRUSTED_AUTHSERVID=my-auth-serv-id
export MILTER_X509_ENABLED=yepp
export MILTER_X509_TRUSTED_CN=mail.protection.outlook.com
export MILTER_ADD_HEADER=yepp
export MILTER_AUTHSERVID=my-auth-serv-id
```

# Shell-1: start ExOTA-Milter
```
. venv/bin/activate
python3 app/exota-milter.py
```

# Shell-2: execute `miltertest`
This must be done only once: `export MILTER_SOCKET=/tmp/exota-milter`

Execute miltertest pointing to the test script written in lua to feed the **ExOTA-Milter**:

`miltertest -v -D socket="${MILTER_SOCKET}" -s tests/miltertest.lua`