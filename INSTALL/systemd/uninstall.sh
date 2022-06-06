#!/bin/sh

if [ "$(id -u)" != "0" ]; then
  echo "You must be root!"
  exit 1
fi

systemctl disable exota-milter.service
systemctl stop exota-milter.service
rm -rf /usr/local/exota-milter/
rm -f /usr/local/sbin/exota-milter.sh
rm -f /lib/systemd/system/exota-milter.service
systemctl daemon-reload
echo "/etc/exota-milter/ was kept undeleted!"