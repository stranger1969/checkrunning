#!/bin/sh

[ -f /var/run/deluid.pid ] && exit -1

echo $$ > /var/run/deluid.pid 

US="$1"
if [ "x${US}" = "x" ]
then
	echo " Usage $0 <UID>"
	exit 1
fi

UIDList=`cat /etc/checkrunning.conf | grep uid | sed 's/uid = //'`
cat /etc/checkrunning.conf | grep -v uid > /etc/checkrunning.conf.new

UIDList=`echo $UIDList | sed -e "s/\b$1\b//"`

echo "uid = ${UIDList}" >> /etc/checkrunning.conf.new

mv /etc/checkrunning.conf.new /etc/checkrunning.conf

rm -f /var/run/deluid.pid
