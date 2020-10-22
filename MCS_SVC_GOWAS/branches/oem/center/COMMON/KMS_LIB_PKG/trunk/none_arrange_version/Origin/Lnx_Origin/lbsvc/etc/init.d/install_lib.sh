#!/bin/sh

ARGC=$#

INSTALL_DAEMON_PATH=$1
INSTALL_OPSHELL_PATH=$INSTALL_DAEMON_PATH/op-shell
INSTALL_UTIL_SHELL_PATH=$INSTALL_OPSHELL_PATH/misc
INSTALL_CFG_PATH=$INSTALL_DAEMON_PATH/cfg
#INSTALL_LIB_PATH=$INSTALL_DAEMON_PATH/libs
INSTALL_LIB_PATH=/usr/local/lib/mcsed

SOURCE_ROOT_PATH=$INSTALL_DAEMON_PATH/etc/init.d
SOURCE_DAEMON_BIN_PATH=$SOURCE_ROOT_PATH/bins
SOURCE_OPSHELL_PATH=$SOURCE_ROOT_PATH/op-shell
SOURCE_UTIL_SHELL_PATH=$SOURCE_OPSHELL_PATH/misc
SOURCE_CFG_PATH=$SOURCE_ROOT_PATH/cfg
SOURCE_LIB_PATH=$SOURCE_ROOT_PATH/libs

RULE_SHELL_PATH=$SOURCE_UTIL_SHELL_PATH

UTIL_SHELL=$SOURCE_UTIL_SHELL_PATH/util.sh

source $UTIL_SHELL $SOURCE_UTIL_SHELL_PATH

OS=`get_os`
FULL_VER=`get_ver "FULL_VERSION"`
MAJOR_VER=`get_ver "MAJOR_VERSION"`
MINOR_VER=`get_ver "MINOR_VERSION"`
BIT=`get_bit`
OS_FULL_NAME=$OS\_$MAJOR_VER\.$MINOR_VER\_$BIT

DAEMON_NAME=$2

POLICY_MAJOR_VER=`get_policy_os_major_ver`
POLICY_MINOR_VER=`get_policy_os_minor_ver`
POLICY_BIT=`get_policy_os_bit`

install_lib()
{
  INSTALL_LIB=1
  FIND_DIR_NAME=

  DIR_NAME=$OS\_$MAJOR_VER\.$MINOR_VER\_$BIT
  printf >&1 "[ \033[33m%-50s\033[0m ] %-40s \n" $DIR_NAME "Library Searching..."

  `mkdir -p $INSTALL_LIB_PATH`

  while [ $MINOR_VER -ge "0" ]
    do
      DIR_NAME=$OS\_$MAJOR_VER\.$MINOR_VER\_$BIT
      RESULT=`find $SOURCE_LIB_PATH -name $DIR_NAME`
      if [ "$POLICY_MINOR_VER" == "strict" ] && [ "$POLICY_BIT" == "strict" ]
        then
          if [ -z $RESULT ]
            then
                printf >&1 "[ \033[33m%-50s\033[0m ] \033[31m%-40s\033[0m\n" $OS_FULL_NAME "Can't Find Suitable Library... Exit Install"
                exit 1
            else
            FIND_DIR_NAME=`echo $RESULT |sed -e 's%^.*./%%'`
            printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Library..."
            `rm -rf $INSTALL_LIB_PATH`
            `cp -r $SOURCE_LIB_PATH/$FIND_DIR_NAME $INSTALL_LIB_PATH`
            if [ -d $INSTALL_LIB_PATH ]
              then
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
              else
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                exit 1
            fi
            break
          fi
      elif [ "$POLICY_MINOR_VER" == "flexible" ] && [ "$POLICY_BIT" == "strict" ]
        then
          if [ -z $RESULT ]
            then
              if [ $INSTALL_LIB == 1 ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[36m%-40s\033[0m\n" $DIR_NAME "Searching Another Version..."
                  INSTALL_LIB=0
              fi
              MINOR_VER=$(($MINOR_VER-1))
              if [ $MAJOR_VER != "0" ] && [ $MINOR_VER == "-1" ] && [ $POLICY_MAJOR_VER == "flexible" ]
                then
                  MAJOR_VER=$(($MAJOR_VER-1))
                  MINOR_VER="9"
              fi
          else
            FIND_DIR_NAME=`echo $RESULT |sed -e 's%^.*./%%'`
            printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Library..."
            `rm -rf $INSTALL_LIB_PATH`
            `cp -r $SOURCE_LIB_PATH/$FIND_DIR_NAME $INSTALL_LIB_PATH`
            if [ -d $INSTALL_LIB_PATH ]
              then
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
              else
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                exit 1
            fi
            break
        fi
      elif [ "$POLICY_MINOR_VER" == "strict" ] && [ "$POLICY_BIT" == "flexible" ]
        then
          if [ -z $RESULT ]
            then
              if [ $INSTALL_LIB == 1 ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[36m%-40s\033[0m\n" $DIR_NAME "Searching Another Version..."
                  INSTALL_LIB=0
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
            printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Library..."
            `rm -rf $INSTALL_LIB_PATH`
            `cp -r $SOURCE_LIB_PATH/$FIND_DIR_NAME $INSTALL_LIB_PATH`
            if [ -d $INSTALL_LIB_PATH ]
              then
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
              else
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                exit 1
            fi
            break
        fi
      elif [ "$POLICY_MINOR_VER" == "flexible" ] && [ "$POLICY_BIT" == "flexible" ]
        then
          if [ -z $RESULT ]
            then
              if [ $INSTALL_LIB == 1 ]
                then
                  printf >&1 "[ \033[33m%-50s\033[0m ] \033[36m%-40s\033[0m\n" $DIR_NAME "Searching Another Version..."
                  INSTALL_LIB=0
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
            printf >&1 "[ \033[33m%-50s\033[0m ] \033[32m%-40s\033[0m\n" $FIND_DIR_NAME "Seleted Library..."
            `rm -rf $INSTALL_LIB_PATH`
            `cp -r $SOURCE_LIB_PATH/$FIND_DIR_NAME $INSTALL_LIB_PATH`
            if [ -d $INSTALL_LIB_PATH ]
              then
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" $FIND_DIR_NAME "Install"
              else
                printf >&1 "[ \033[33m%-50s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" $FIND_DIR_NAME "Install"
                exit 1
            fi
            break
        fi

      fi
  done

  if [ $MINOR_VER == "-1" ]
    then
      printf >&1 "[ \033[33m%-50s\033[0m ] \033[31m%-40s\033[0m\n" $OS_FULL_NAME "Can't Find Suitable Library... Exit Install"
      exit 1
  fi

  BIT='get_bit'
}

install_lib

exit 0
