#!/bin/sh

ulimit -c unlimited

ARGC=$#
CMD=$1
RUN_OPTION=$2

MY_FILE_NAME="${0##*/}"

CUR_PATH=$PWD
TEMP_DAEMON_SHELL_PATH=`echo $0 |sed -e 's%/'$MY_FILE_NAME'.*$%%'`

cd $TEMP_DAEMON_SHELL_PATH
DAEMON_SHELL_PATH=$PWD
cd $CUR_PATH

INSTALL_DAEMON_PATH=`echo $DAEMON_SHELL_PATH |sed -e 's%/op-shell.*$%%'`
INSTALL_OPSHELL_PATH=$INSTALL_DAEMON_PATH/op-shell
INSTALL_UTIL_SHELL_PATH=$INSTALL_OPSHELL_PATH/misc
INSTALL_CFG_PATH=$INSTALL_DAEMON_PATH/cfg
INSTALL_LIB_PATH=$INSTALL_DAEMON_PATH/libs

SOURCE_ROOT_PATH=$INSTALL_DAEMON_PATH/etc/init.d
SOURCE_DAEMON_BIN_PATH=$SOURCE_ROOT_PATH/bins
SOURCE_OPSHELL_PATH=$SOURCE_ROOT_PATH/op-shell
SOURCE_UTIL_SHELL_PATH=$SOURCE_OPSHELL_PATH/misc
SOURCE_CFG_PATH=$SOURCE_ROOT_PATH/cfg
SOURCE_LIB_PATH=$SOURCE_ROOT_PATH/libs

UTIL_SHELL=$SOURCE_UTIL_SHELL_PATH/util.sh

source $UTIL_SHELL $UTIL_SHELL_PATH

DAEMON_NAME=`echo $INSTALL_DAEMON_PATH|rev |sed 's%/.*$%%' |rev`
DAEMON_SHELL_PATH=$INSTALL_OPSHELL_PATH
DAEMON_SHELL_NAME=$DAEMON_NAME\.sh

cd $INSTALL_DAEMON_PATH

daemon_start()
{
  DAEMON_PID=`get_pid $DAEMON_NAME`

  if [ -z $DAEMON_PID ]
    then
      $INSTALL_DAEMON_PATH/$DAEMON_NAME $RUN_OPTION
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[33m$INSTALL_DAEMON_PATH/$DAEMON_NAME $RUN_OPTION\033[0m ]\n" $DAEMON_NAME "Try to Start... with"
      sleep 2

      DAEMON_PID=`get_pid $DAEMON_NAME`

      if [ -z $DAEMON_PID ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $DAEMON_NAME "Start"
          exit 1
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $DAEMON_NAME "Start"
      fi
  else
    printf >&2 "[ \033[33m%-39s\033[0m ] %-40s\n" $DAEMON_NAME "Already Running..."
  fi
}

daemon_stop()
{
  DAEMON_PID=`get_pid $DAEMON_NAME`
  FLAG=$1
  
  if [ -z $DAEMON_PID ]
    then
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s\n" $DAEMON_NAME "Already Stop..."
    else
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s\n" $DAEMON_NAME "Try to Stop..."

      kill -9 $DAEMON_PID
      sleep 1

      DAEMON_PID=`get_pid $DAEMON_NAME`

      if [ -z $DAEMON_PID ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $DAEMON_NAME "Stop"
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $DAEMON_NAME "Stop"
          exit 1
      fi
  fi  
}

daemon_status()
{
  DAEMON_PID=`get_pid $DAEMON_NAME`

  if [ -z $DAEMON_PID ]
    then
      printf >&2 "[ \033[33m%-39s\033[0m ] is \033[31mNot Running...\033[0m\n" $DAEMON_NAME
    else
      printf >&2 "[ \033[33m%-39s\033[0m ] is \033[32mRunning...\033[0m\n" $DAEMON_NAME
  fi
}

daemon_main()
{
  if [ 2 -eq $ARGC ]
    then
      if [ $CMD == "start" ]
        then
          daemon_start "$RUN_OPTION"
      elif [ $CMD == "restart" ]
        then
          daemon_stop
          daemon_start "$RUN_OPTION"
      else
        printf >&2 "ussage : ./%s.sh start [run_option]\n" $DAEMON_NAME
        exit 1
      fi
  elif [ 1 -eq $ARGC ]
    then
      if [ $CMD == "stop" ]
        then
          daemon_stop
      elif [ $CMD == "status" ]
        then
          daemon_status
      else
        echo >&2 "./$DAEMON_NAME.sh [start [run_option]|stop|status|restart [run_option]]" 
      fi
  else
      echo >&2 "./$DAEMON_NAME.sh [start [run_option]|stop|status|restart [run_option]]"
  fi
}

daemon_main

cd $CUR_PATH
exit 0
