# How to install ExOTA-Milter

#### Table of contents
[docker-compose](#docker-compose)  
[kubernetes](#kubernetes)  
[systemd](#systemd)  

## docker-compose <a name="docker-compose"/>
```
~/src/ExOTA-Milter/INSTALL/docker-compose$ docker-compose up
[+] Running 2/2
 ⠿ Network docker-compose_default           Created                                                                                                                                                                                     0.8s
 ⠿ Container docker-compose-exota-milter-1  Created                                                                                                                                                                                     0.1s
Attaching to docker-compose-exota-milter-1
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,503: INFO 140529821924168 Logger initialized
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,503: INFO 140529821924168 ENV[MILTER_NAME]: exota-milter
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,503: INFO 140529821924168 ENV[MILTER_SOCKET]: inet:4321@0.0.0.0
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_REJECT_MESSAGE]: CUSTOMIZE THIS! - Security policy violation!!
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_TMPFAIL_MESSAGE]: Service temporarily not available! Please try again later.
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_TRUSTED_AUTHSERVID]: dkimauthservid
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_DKIM_ALIGNMENT_REQUIRED]: True
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_DKIM_ENABLED]: True
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_X509_TRUSTED_CN]: mail.protection.outlook.com
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_X509_IP_WHITELIST]: ['127.0.0.1', '::1']
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,504: INFO 140529821924168 ENV[MILTER_X509_ENABLED]: True
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,505: INFO 140529821924168 ENV[MILTER_AUTHSERVID]: ThisAuthservID
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,505: INFO 140529821924168 ENV[MILTER_ADD_HEADER]: True
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,505: INFO 140529821924168 ENV[MILTER_POLICY_SOURCE]: file
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,505: INFO 140529821924168 ENV[MILTER_POLICY_FILE]: /data/exota-milter-policy.json
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,511: INFO 140529821924168 JSON policy backend initialized
docker-compose-exota-milter-1  | 2022-06-06 21:54:04,511: INFO 140529821924168 Startup exota-milter@socket: inet:4321@0.0.0.0
```

## kubernetes <a name="kubernetes"/>
By default this example installs the Exota-milter workload into the `exota-milter` namespace, which must be created in advance:
```
kubectl create ns exota-milter

namespace/exota-milter created
```
Deploy stateless workload (type `Deployment`) with `kustomize`:
```
~/src/ExOTA-Milter/INSTALL/kubernetes$ kubectl apply -k .

configmap/exota-milter-policy-cmap created
service/exota-milter created
deployment.apps/exota-milter created
```
Check status of pods, replica-sets and cluster internal service:
```
~/src/ExOTA-Milter/INSTALL/kubernetes$ kubectl -n exota-milter get all
NAME                                READY   STATUS    RESTARTS   AGE
pod/exota-milter-547dbccd8b-j69mn   1/1     Running   0          64s
pod/exota-milter-547dbccd8b-7hl6c   1/1     Running   0          64s
pod/exota-milter-547dbccd8b-k4ng8   1/1     Running   0          64s

NAME                   TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
service/exota-milter   ClusterIP   10.43.78.163   <none>        4321/TCP   61s

NAME                           READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/exota-milter   3/3     3            3           64s

NAME                                      DESIRED   CURRENT   READY   AGE
replicaset.apps/exota-milter-547dbccd8b   3         3         3       65s
```
Get logs of the pods:
```
~/src/ExOTA-Milter/INSTALL/kubernetes$ kubectl -n exota-milter logs -l app=exota-milter
2022-06-06 21:57:03,515: INFO Logger initialized
2022-06-06 21:57:03,515: INFO ENV[MILTER_NAME]: exota-milter
2022-06-06 21:57:03,515: INFO ENV[MILTER_SOCKET]: inet:4321@127.0.0.1
2022-06-06 21:57:03,515: INFO ENV[MILTER_REJECT_MESSAGE]: Security policy violation!!
2022-06-06 21:57:03,515: INFO ENV[MILTER_TMPFAIL_MESSAGE]: Service temporarily not available! Please try again later.
2022-06-06 21:57:03,515: INFO ENV[MILTER_TRUSTED_AUTHSERVID]: dkimauthservid
2022-06-06 21:57:03,515: INFO ENV[MILTER_DKIM_ALIGNMENT_REQUIRED]: True
2022-06-06 21:57:03,515: INFO ENV[MILTER_DKIM_ENABLED]: True
2022-06-06 21:57:03,515: INFO ENV[MILTER_X509_TRUSTED_CN]: mail.protection.outlook.com
2022-06-06 21:57:03,515: INFO ENV[MILTER_X509_IP_WHITELIST]: ['127.0.0.1', '::1']
2022-06-06 21:57:03,515: INFO ENV[MILTER_X509_ENABLED]: True
2022-06-06 21:57:03,516: INFO ENV[MILTER_AUTHSERVID]: some-auth-serv-id
2022-06-06 21:57:03,516: INFO ENV[MILTER_ADD_HEADER]: True
2022-06-06 21:57:03,516: INFO ENV[MILTER_POLICY_SOURCE]: file
2022-06-06 21:57:03,516: INFO ENV[MILTER_POLICY_FILE]: /data/exota-milter-policy.json
2022-06-06 21:57:03,516: INFO JSON policy backend initialized
2022-06-06 21:57:03,516: INFO Startup exota-milter@socket: inet:4321@127.0.0.1
```
Remove workload from cluster:
```
~/src/ExOTA-Milter/INSTALL/kubernetes$ kubectl delete -k .

configmap "exota-milter-policy-cmap" deleted
service "exota-milter" deleted
deployment.apps "exota-milter" deleted

~/src/ExOTA-Milter/INSTALL/kubernetes$ kubectl delete ns exota-milter

namespace "exota-milter" deleted
```

## systemd <a name="systemd"/>
If you do not want to run the ExOTA-Milter in a containerized environment but directly as a systemd-unit/-service, first you´ll need to install all necessary python and build dependencies. Start with build deps (examples refere to ubuntu/debian):
```
sudo apt install --no-install-recommends gcc libpython3-dev libmilter-dev python3-pip
```
Now install all python dependencies:
```
~/src/ExOTA-Milter/INSTALL/systemd# sudo pip3 install -r ../../requirements.txt
Requirement already satisfied: authres==1.2.0 in /usr/local/lib/python3.8/dist-packages (from -r ../../requirements.txt (line 1)) (1.2.0)
Requirement already satisfied: pymilter==1.0.4 in /usr/local/lib/python3.8/dist-packages (from -r ../../requirements.txt (line 2)) (1.0.4)
Requirement already satisfied: ldap3 in /usr/local/lib/python3.8/dist-packages (from -r ../../requirements.txt (line 3)) (2.9.1)
Requirement already satisfied: pyasn1>=0.4.6 in /usr/local/lib/python3.8/dist-packages (from ldap3->-r ../../requirements.txt (line 3)) (0.4.8)
```
At last uninstall all build dependencies, as they are not needed anymore:
```
apt purge gcc libpython3-dev libmilter-dev python3-pip
```
Next you should be able to install the ExOTA-Milter as well as the systemd-stuff by running the `install.sh` script:
```
~/src/ExOTA-Milter/INSTALL/systemd$ sudo ./install.sh
Created symlink /etc/systemd/system/multi-user.target.wants/exota-milter.service → /lib/systemd/system/exota-milter.service.
```
Use the `uninstall.sh` script to uninstall the ExOTA-Milter from your systemd environment. Files under `/etc/exota-milter/` (config and policy) are kept undeleted!
