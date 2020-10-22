#!/bin/sh

ARGC=$#

CUR_PATH=$PWD
TEMP_INSTALL_SHELL_PATH=`echo $0 |sed -e 's%/install.sh.*$%%'`

cd $TEMP_INSTALL_SHELL_PATH
INSTALL_SHELL_PATH=$PWD
cd $CUR_PATH

INSTALL_DAEMON_PATH=`echo $INSTALL_SHELL_PATH |sed -e 's%/etc.*$%%'`
INSTALL_OPSHELL_PATH=$INSTALL_DAEMON_PATH/op-shell
INSTALL_UTIL_SHELL_PATH=$INSTALL_OPSHELL_PATH/misc
INSTALL_CFG_PATH=$INSTALL_DAEMON_PATH/cfg
INSTALL_LIB_PATH=$INSTALL_DAEMON_PATH/libs

SOURCE_ROOT_PATH=$INSTALL_DAEMON_PATH/etc/init.d
SOURCE_PAGES_PATH=$SOURCE_ROOT_PATH/pages
SOURCE_DAEMON_BIN_PATH=$SOURCE_ROOT_PATH/bins
SOURCE_OPSHELL_PATH=$SOURCE_ROOT_PATH/op-shell
SOURCE_UTIL_SHELL_PATH=$SOURCE_OPSHELL_PATH/misc
SOURCE_CFG_PATH=$SOURCE_ROOT_PATH/cfg
SOURCE_LIB_PATH=$SOURCE_ROOT_PATH/libs

RULE_SHELL_PATH=$SOURCE_UTIL_SHELL_PATH

UTIL_SHELL=$SOURCE_UTIL_SHELL_PATH/util.sh

source $UTIL_SHELL $SOURCE_UTIL_SHELL_PATH

OS=`get_os`
MAJOR_VER=`get_ver "MAJOR_VERSION"`
MINOR_VER=`get_ver "MINOR_VERSION"`
BIT=`get_bit`
OS_FULL_NAME=$OS\_$MAJOR_VER\.$MINOR_VER\_$BIT

DAEMON_NAME=`echo $INSTALL_DAEMON_PATH|rev |sed 's%/.*$%%' |rev`
WEB_SERVER_DAEMON_NAME=stat_web_server

POLICY_MAJOR_VER=`get_policy_os_major_ver`
POLICY_MINOR_VER=`get_policy_os_minor_ver`
POLICY_BIT=`get_policy_os_bit`

install_prepare_shell_script()
{
  rm -rf $INSTALL_OPSHELL_PATH
  if [ -d $INSTALL_OPSHELL_PATH ]
    then
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $INSTALL_OPSHELL_PATH "Prepare Shell Directory"
      exit 1
    else
      mkdir -p $INSTALL_OPSHELL_PATH
      
      if [ -d $INSTALL_OPSHELL_PATH ]
        then
          printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $INSTALL_OPSHELL_PATH "Prepare Shell Directory"
      fi
  fi

  `cp -r $SOURCE_UTIL_SHELL_PATH $INSTALL_OPSHELL_PATH`
  if [ -d $INSTALL_UTIL_SHELL_PATH ]
    then
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $INSTALL_UTIL_SHELL_PATH "Install"
    else
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $INSTALL_UTIL_SHELL_PATH "Install"
      exit 1
  fi

  DAEMON_SHELL_NAME=$DAEMON_NAME\.sh
  
  `cp $SOURCE_OPSHELL_PATH/daemon.sh $INSTALL_OPSHELL_PATH/$DAEMON_SHELL_NAME`
  if [ -e $INSTALL_OPSHELL_PATH/$DAEMON_SHELL_NAME ]
    then
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $DAEMON_SHELL_NAME "Install"
    else
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $DAEMON_SHELL_NAME "Install"
      exit 1
  fi
}

install_cfg()
{
  `rm -rf $INSTALL_CFG_PATH`
  `cp -r $SOURCE_CFG_PATH $INSTALL_DAEMON_PATH`
  if [ -d $INSTALL_CFG_PATH ]
    then
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $INSTALL_CFG_PATH "Install"
    else
      printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $INSTALL_CFG_PATH "Install"
      exit 1
  fi
}

install_main_binary()
{
  INSTALL_BIN=1
  DIR_NAME=$OS\_$MAJOR_VER\.$MINOR_VER\_$BIT
  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s \n" $DIR_NAME "Binary Searching..."

  while [ $MINOR_VER -ge "0" ]
    do
      DIR_NAME=$OS\_$MAJOR_VER\.$MINOR_VER\_$BIT
      RESULT=`find $SOURCE_DAEMON_BIN_PATH -name $DIR_NAME`
      if [ "$POLICY_MINOR_VER" == "strict" ] && [ "$POLICY_BIT" == "strict" ]
        then
          if [ -z $RESULT ]
            then
              printf >&1 "[ \033[33m%-50s\033[0m ] \033[31m%-40s\033[0m\n" $OS_FULL_NAME "Can't Find Suitable Binary... Exit Install"
              exit 1
            else
              FIND_DIR_NAME=`echo $RESULT |sed -e 's%^.*./%%'`
              printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Binary..."
              `cp $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$DAEMON_NAME $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                  exit 1
              fi

              `cp $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$WEB_SERVER_DAEMON_NAME $INSTALL_DAEMON_PATH`
              `cp -r $SOURCE_PAGES_PATH $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$WEB_SERVER_DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                  exit 1
              fi

              break
          fi
      elif [ "$POLICY_MINOR_VER" == "flexible" ] && [ "$POLICY_BIT" == "strict" ]
        then
          if [ -z $RESULT ]
            then
              if [ $INSTALL_BIN == 1 ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[36m%-40s\033[0m\n" $DIR_NAME "Searching Another Version..."
                  INSTALL_BIN=0
              fi

              MINOR_VER=$(($MINOR_VER-1))
              if [ $MAJOR_VER != "0" ] && [ $MINOR_VER == "-1" ] && [ $POLICY_MAJOR_VER == "flexible" ]
                then
                  MAJOR_VER=$(($MAJOR_VER-1))
                  MINOR_VER="9"
              fi
            else
              FIND_DIR_NAME=`echo $RESULT |sed -e 's%^.*./%%'`
              printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Binary..."
              `cp -r $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$DAEMON_NAME $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                  exit 1
              fi

              `cp -r $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$WEB_SERVER_DAEMON_NAME $INSTALL_DAEMON_PATH`
              `cp -r $SOURCE_PAGES_PATH $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$WEB_SERVER_DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                  exit 1
              fi

              break
          fi
      elif [ "$POLICY_MINOR_VER" == "strict" ] && [ "$POLICY_BIT" == "flexible" ]
        then
          if [ -z $RESULT ]
            then
              if [ $INSTALL_BIN == 1 ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[36m%-40s\033[0m\n" $DIR_NAME "Searching Another Version..."
                  INSTALL_BIN=0
              fi
              ORI_BIT=`get_bit`
              if [ $BIT == "32" ]
                then
                  BIT="64"
                else
                  BIT="32"
              fi

              if [ $BIT == $ORI_BIT ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[31m%-40s\033[0m\n" $OS_FULL_NAME "Can't Find Suitable Binary... Exit Install"
                  exit 1
              fi
            else
              FIND_DIR_NAME=`echo $RESULT |sed -e 's%^.*./%%'`
              printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Binary..."
              `cp -r $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$DAEMON_NAME $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                  exit 1
              fi

              `cp -r $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$WEB_SERVER_DAEMON_NAME $INSTALL_DAEMON_PATH`
              `cp -r $SOURCE_PAGES_PATH $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$WEB_SERVER_DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                  exit 1
              fi

              break
          fi
      elif [ "$POLICY_MINOR_VER" == "flexible" ] && [ "$POLICY_BIT" == "flexible" ]
        then
          if [ -z $RESULT ]
            then
              if [ $INSTALL_BIN == 1 ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[36m%-40s\033[0m\n" $DIR_NAME "Searching Another Version..."
                  INSTALL_BIN=0
              fi
              ORI_BIT=`get_bit`
              if [ $BIT == "32" ]
                then
                  BIT="64"
                else
                  BIT="32"
              fi

              if [ $BIT == $ORI_BIT ]
                then
                  MINOR_VER=$(($MINOR_VER-1))
                  if [ $MAJOR_VER != "0" ] && [ $MINOR_VER == "-1" ] && [ $POLICY_MAJOR_VER == "flexible" ]
                    then
                      MAJOR_VER=$(($MAJOR_VER-1))
                      MINOR_VER="9"
                  fi
              fi
            else
              FIND_DIR_NAME=`echo $RESULT |sed -e 's%^.*./%%'`
              printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Binary..."
              `cp -r $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$DAEMON_NAME $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                  exit 1
              fi

              `cp -r $SOURCE_DAEMON_BIN_PATH/$FIND_DIR_NAME/$WEB_SERVER_DAEMON_NAME $INSTALL_DAEMON_PATH`
              `cp -r $SOURCE_PAGES_PATH $INSTALL_DAEMON_PATH`
              if [ -e $INSTALL_DAEMON_PATH/$WEB_SERVER_DAEMON_NAME ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                else
                  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $WEB_SERVER_DAEMON_NAME "Install"
                  exit 1
              fi

              break
          fi
      fi
  done

  if [ $MINOR_VER == "-1" ]
    then
      printf >&1 "[ \033[33m%-50s\033[0m ] \033[31m%-40s\033[0m\n" $OS_FULL_NAME "Can't Find Suitable Binary... Exit Install"
      exit 1
  fi

  BIT='get_bit'
}

install_iptables_rule()
{
  SOURCE_IP="IP_NOT_EXIST"
  TCP_PORT=9600
  TCP_PORT_01=9100

  `$RULE_SHELL_PATH/rule.sh $DAEMON_NAME $MAJOR_VER del_all INPUT > /dev/null 2>&1`
  `$RULE_SHELL_PATH/rule.sh $DAEMON_NAME $MAJOR_VER add INPUT $SOURCE_IP tcp dport $TCP_PORT ACCEPT > /dev/null 2>&1`
  `$RULE_SHELL_PATH/rule.sh $DAEMON_NAME $MAJOR_VER add INPUT $SOURCE_IP tcp dport $TCP_PORT_01 ACCEPT > /dev/null 2>&1`

}

install_main()
{
  `ulimit -c unlimited`

  install_prepare_shell_script
  install_cfg
  install_main_binary
#  install_iptables_rule
  $SOURCE_ROOT_PATH/install_lib.sh $INSTALL_DAEMON_PATH $DAEMON_NAME
}

install_main

exit 0
