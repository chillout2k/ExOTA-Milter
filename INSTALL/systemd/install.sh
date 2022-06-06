#!/bin/sh

if [ "$(id -u)" != "0" ]; then
  echo "You must be root!"
  exit 1
fi

install -d /usr/local/exota-milter/
install ../../app/*.py /usr/local/exota-milter/
install -m 750 exota-milter.sh /usr/local/sbin/exota-milter.sh
install -d -m 660 /etc/exota-milter
if [ -e /etc/exota-milter/exota-milter-policy.json ]; then
  echo "Found existing /etc/exota-milter/exota-milter-policy.json - skipping"
else
  install -m 660 exota-milter-policy.json /etc/exota-milter/exota-milter-policy.json
fi
if [ -e /etc/exota-milter/exota-milter.conf ]; then
  echo "Found existing /etc/exota-milter/exota-milter.conf - skipping"
else
  install -m 750 exota-milter.conf /etc/exota-milter/exota-milter.conf
fi
install -m 660 exota-milter.service /lib/systemd/system/exota-milter.service
systemctl daemon-reload
systemctl enable exota-milter.service
