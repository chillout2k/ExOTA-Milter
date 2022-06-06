#!/bin/sh

if [ ! -e /etc/exota-milter/exota-milter.conf ]; then
  echo "Missing /etc/exota-milter/exota-milter.conf!"
  exit 1;
fi

if [ ! -e /etc/exota-milter/exota-milter-policy.json ]; then
  echo "Missing /etc/exota-milter/exota-milter-policy.json!"
  exit 1;
fi

. /etc/exota-milter/exota-milter.conf

exec /usr/bin/python3 /usr/local/exota-milter/exota-milter.py 2>&1
