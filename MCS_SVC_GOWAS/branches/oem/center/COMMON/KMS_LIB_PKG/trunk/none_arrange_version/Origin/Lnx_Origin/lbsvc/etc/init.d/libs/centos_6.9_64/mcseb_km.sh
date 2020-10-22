#!/bin/bash

LSMOD=$(lsmod |grep $2 |wc -l)
BASEDIR=$(dirname "$0")

if [ $1 = 0 ]
then
  rmmod $BASEDIR/$2.ko
#  echo "rmmod $2.ko"
else
  if [ $LSMOD = 1 ]
  then
    rmmod $BASEDIR/$2.ko
    insmod $BASEDIR/$2.ko
#    echo "Exist insmod $2.ko"
  else
    insmod $BASEDIR/$2.ko
#    echo "Not exist insmod $2.ko"
  fi
fi

