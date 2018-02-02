#!/bin/sh

[ -f /var/run/adduid.pid ] && exit -1

echo $$ > /var/run/adduid.pid 

US="$1"
if [ "x${US}" = "x" ]
then
	echo " Usage $0 <UID>"
	exit 1
fi

UIDList=`cat /etc/checkrunning.conf | grep uid | sed 's/uid = //'`
cat /etc/checkrunning.conf | grep -v uid > /etc/checkrunning.conf.new

echo $UIDList
echo $1

UIDList=`echo $UIDList | sed -e "s/\ $1\b//"`
echo "uid = ${UIDList} $1" >> /etc/checkrunning.conf.new

mv /etc/checkrunning.conf.new /etc/checkrunning.conf

rm -f /var/run/adduid.pid
