#!/bin/sh

UTIL_SHELL_PATH=$1

get_os()
{
  read ISSUE < "/etc/redhat-release"
  TOKEN=($ISSUE)
  OS=`echo ${TOKEN[0]}|tr '[A-Z]' '[a-z]'`
  echo $OS
}

get_ver()
{
  VER_TYPE=$1
  read ISSUE < "/etc/redhat-release"
  VER=`echo $ISSUE |sed 's/[^0-9.]//g'`
  IFS='.'
  VER_TOKEN=($VER)

  MAJOR_VER=${VER_TOKEN[0]}
  MINOR_VER=${VER_TOKEN[1]}
  IFS=' '

  if [ $VER_TYPE == "MAJOR_VERSION" ]
    then
      echo $MAJOR_VER
    elif [ $VER_TYPE == "MINOR_VERSION" ]
      then
        echo $MINOR_VER
    elif [ $VER_TYPE == "FULL_VERSION" ]
      then
        echo $VER
    else
      echo "Unknown Version Type"
  fi
}

get_bit()
{
  BIT=`getconf LONG_BIT`
  echo $BIT
}

get_policy_os_major_ver()
{
  POLICY_OS_MAJOR_VER=`grep "POLICY_OS_MAJOR_VERSION" $UTIL_SHELL_PATH/shell.cfg |sed -e 's% %%g' -e 's%^.*=%%'`
  echo $POLICY_OS_MAJOR_VER
}

get_policy_os_minor_ver()
{
  POLICY_OS_MINOR_VER=`grep "POLICY_OS_MINOR_VERSION" $UTIL_SHELL_PATH/shell.cfg |sed -e 's% %%g' -e 's%^.*=%%'`
  echo $POLICY_OS_MINOR_VER
}

get_policy_os_bit()
{
  POLICY_OS_BIT=`grep "POLICY_OS_BIT" $UTIL_SHELL_PATH/shell.cfg |sed -e 's% %%g' -e 's%^.*=%%'`
  echo $POLICY_OS_BIT
}

get_pid()
{
  DAEMON_NAME=$1
  DAEMON_PID=$(/sbin/pidof -x $DAEMON_NAME)
  echo $DAEMON_PID
}

get_file_path()
{
  FILE_NAME=$1
  FILE_PATH=`find $PWD -name $FILE_NAME`
  echo $FILE_PATH
}

check_exist_directory()
{
  DIRECTORY=$1
  if [ -d "$DIRECTORY" ]
    then
      RESULT=0
      echo $RESULT
    else
      RESULT=-1
      echo $RESULT
  fi
}
