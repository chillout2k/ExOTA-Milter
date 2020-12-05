# How to build and deploy ExOTA-Milter as an OCI container
## Build with `docker-cli`
Actually I´m going with docker-ce to build the container image, but same results should come out with e.g. [img](https://github.com/genuinetools/img) etc.

Run following command in the root directory of this repo:
```
docker build -t exota-milter:local -f OCI/Dockerfile .
[...]
Successfully built 9cceb121f604
Successfully tagged exota-milter:local
```

## Deploy with `docker-compose`
Prerequisites: `docker-compose` installed
* Create a deployment directory and jump into it. In my case it´s `/docker/containers/exota-milter`
  * `install -d /docker/containers/exota-milter`
  * `cd /docker/containers/exota-milter`
* Create further directories in the deployment directory: 
  * `install -d -m 777 data`. The application expects the policy file in `/data/policy.json` (path inside the container!).
  * `install -d -m 777 socket`. The application places the milter socket file under `/socket/exota-milter` (path inside the container!)
* Create the policy file `data/policy.json` with following content:
```
{
  "yad.onmicrosoft.com": {
    "tenant_id": "1234abcd-18c5-45e8-88de-123456789abc",
    "dkim_enabled": true
  },
  "example.com": {
    "tenant_id": "abcd1234-18c5-45e8-88de-987654321cba",
    "dkim_enabled": false
  }
}
```
* Create a file named `docker-compose.yml` in the deployment directory with following content:
```
version: '2.4'

services:
  exota-milter:
    image: exota-milter:local
    environment:
      LOG_LEVEL: 'debug'
      MILTER_SOCKET: '/socket/exota-milter'
      #MILTER_SOCKET: 'inet:123456@0.0.0.0'
      MILTER_POLICY_FILE: '/data/policy.json'
      MILTER_DKIM_ENABLED: 'some_value'
      MILTER_TRUSTED_AUTHSERVID: 'my-auth-serv-id'
      MILTER_X509_ENABLED: 'some_value'
      MILTER_X509_TRUSTED_CN: 'mail.protection.outlook.com'
      MILTER_ADD_HEADER: 'some_value'
      MILTER_AUTHSERVID: 'my-auth-serv-id'
    volumes:
    - "./data/:/data/:ro"
    - "./socket/:/socket/:rw"
```
If the milter should listen on a TCP-socket instead, just change the value of the `MILTER_SOCKET` ENV-variable to something like `inet:<port>@0.0.0.0`. As IPv6 is supported by the `libmilter` library too, a notation like `inet6:<port>@[::]` is also possible.

* Deploy

Execute `docker-compose up` and if nothing went wrong you shold see following output:
```
Creating network "exota-milter_default" with the default driver
Creating exota-milter_exota-milter_1 ... done
Attaching to exota-milter_exota-milter_1
exota-milter_1  | 2020-11-30 12:38:51,164: INFO ENV[MILTER_SOCKET]: /socket/exota-milter
exota-milter_1  | 2020-11-30 12:38:51,164: INFO ENV[MILTER_REJECT_MESSAGE]: Security policy violation!
exota-milter_1  | 2020-11-30 12:38:51,164: INFO ENV[MILTER_TMPFAIL_MESSAGE]: Service temporarily not available! Please try again later.
exota-milter_1  | 2020-11-30 12:38:51,164: INFO ENV[MILTER_TRUSTED_AUTHSERVID]: my-auth-serv-id
exota-milter_1  | 2020-11-30 12:38:51,165: INFO ENV[MILTER_DKIM_ENABLED]: True
exota-milter_1  | 2020-11-30 12:38:51,165: INFO ENV[MILTER_X509_TRUSTED_CN]: mail.protection.outlook.com
exota-milter_1  | 2020-11-30 12:38:51,165: INFO ENV[MILTER_X509_ENABLED]: True
exota-milter_1  | 2020-11-30 12:38:51,165: INFO ENV[MILTER_POLICY_SOURCE]: file
exota-milter_1  | 2020-11-30 12:38:51,165: INFO ENV[MILTER_POLICY_FILE]: /data/policy.json
exota-milter_1  | 2020-11-30 12:38:51,166: INFO JSON policy backend initialized
exota-milter_1  | 2020-11-30 12:38:51,166: INFO Startup exota-milter@socket: /socket/exota-milter
```

Voila! The milter socket can be accessed on the host filesystem (in my case) under `/docker/containers/exota-milter/socket/exota-milter`.
