#!/bin/bash
clamd
DIRTOSCAN="/var/www /home /opt /usr/bin /etc /usr/sbin";
TODAY=$(date +%u);

if [ "$TODAY" == "6" ];then
 nice -n5 clamdscan -iv / --exclude-dir=/sys/;

else
 for S in ${DIRTOSCAN}; do
  DIRSIZE=$(du -sh "$S" 2>/dev/null | cut -f1);

  clamdscan -iv "$S";
done
fi
ps -ef | grep clamd | grep -v grep | awk '{print $2}' | xargs kill
