#!/bin/sh
ARGC=$#

DAEMON_NAME=$1
OS_MAJOR_VER=$2
#INODE=`ls -i1 |grep -w $DAEMON_NAME\$ |sed -e "s%^ *%%" -e "s% .*$%%"`
#DATE=`stat $DAEMON_NAME |grep Change |sed -e "s%Change:%%" -e "s%^ *%%"`
#ID="$INODE $DATE"
ID=$DAEMON_NAME
CMD=$3
CHAIN=$4
IP=$5
PORT_TYPE=$6
PORT_DIRECTION=$7
PORT_NUM=$8
POLICY=$9

RULE_PATH=/etc/sysconfig/firewall
RULE_FILE=rule_file
if [ $ARGC -gt 4 ] && [ $IP == "IP_NOT_EXIST" ]
  then
    IP_OPTION=""
  else
    IP_OPTION="-s $IP"
fi
WRITE_RULE="iptables -I $CHAIN $IP_OPTION -p $PORT_TYPE --$PORT_DIRECTION $PORT_NUM -j $POLICY"

get_rule_index()
{
  ICMP_RULE_INDEX=`iptables -nL $CHAIN --line-numbers |grep icmp |grep ACCEPT |sed -e 's% .*$%%'`
  let RULE_INDEX=ICMP_RULE_INDEX+1
  echo $RULE_INDEX
}

check_rule()
{
  if [ $OS_MAJOR_VER -eq "7" ]
    then
      CHECK_RULE=`iptables -C $CHAIN $IP_OPTION -p $PORT_TYPE --$PORT_DIRECTION $PORT_NUM -j $POLICY 2> check_rule`
      CHECK_RULE_COUNT=`cat check_rule|grep -c "Bad"`
      if [ $CHECK_RULE_COUNT -eq "1" ]
        then
          CHECK_RULE_RESULT=0
        else
          CHECK_RULE_RESULT=1
      fi
      rm -rf check_rule
    else
      CHECK_RULE_RESULT=`iptables -nL |grep -c "$PORT_NUM"`
  fi
  echo $CHECK_RULE_RESULT
}

check_file_rule()
{
  if [ -f $RULE_PATH/$RULE_FILE ]
    then
      CHECK_FILE_RULE=`cat $RULE_PATH/$RULE_FILE |grep -c "$WRITE_RULE"`
      echo $CHECK_FILE_RULE
    else
      echo "0"
  fi
}

check_file_daemon_rule()
{
  if [ -f $RULE_PATH/$RULE_FILE ]
    then
      CHECK_FILE_DAEMON_RULE=`cat $RULE_PATH/$RULE_FILE |grep -c "$ID"`
      echo $CHECK_FILE_DAEMON_RULE
    else
      echo "0"
  fi
}

check_chain()
{
  if [ $CHAIN == "INPUT" ]
    then
      RULE_FILE=inputrule
  elif [ $CHAIN == "FORWARD" ]
    then
      RULE_FILE=forwardrule
  elif [ $CHAIN == "OUTPUT" ]
    then
      RULE_FILE=outputrule
  else
    printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" "iptables" "Unknown CHAIN... < $CHAIN >"
    exit 1
  fi
}

add_iptables_file()
{
  if [ ! -d $RULE_PATH ]
    then
      mkdir -p $RULE_PATH
  fi

  if [ ! -f $RULE_PATH/$RULE_FILE ]
    then
      touch $RULE_PATH/$RULE_FILE
      chmod +x $RULE_PATH/$RULE_FILE
  fi

  CHECK_FILE_RULE_RESULT=`check_file_rule`

  if [ $CHECK_FILE_RULE_RESULT -eq 0 ]
    then
      ADD_RULE="iptables -I $CHAIN $IP_OPTION -p $PORT_TYPE --$PORT_DIRECTION $PORT_NUM -j $POLICY # $ID"
      echo >&2 "$ADD_RULE" >> $RULE_PATH/$RULE_FILE
      CHECK_FILE_RULE_RESULT=`check_file_rule`
      if [ $CHECK_FILE_RULE_RESULT ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "$ADD_RULE"
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "$ADD_RULE"
          exit 1
      fi
    else
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[36mSKIP\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "$ADD_RULE"
  fi
}

del_iptables_file()
{
  CHECK_FILE_RULE_RESULT=`check_file_rule`

  if [ $CHECK_FILE_RULE_RESULT -eq 0 ]
    then
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[36mSKIP\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "Delete Line $CHAIN $IP_OPTION $PORT_TYPE $PORT_NUM $POLICY"
    else
      `sed -i "/$WRITE_RULE/d" $RULE_PATH/$RULE_FILE`
      CHECK_FILE_RULE_RESULT=`check_file_rule`
      if [ $CHECK_FILE_RULE_RESULT -eq 0 ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "$WRITE_RULE"
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "$WRITE_RULE"
          exit 1
      fi
  fi
}

del_iptables_file_all()
{
  CHECK_FILE_DAEMON_RULE_RESULT=`check_file_daemon_rule`

  if [ $CHECK_FILE_DAEMON_RULE_RESULT -eq 0 ]
    then
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[36mSKIP\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "Delete Line All $ID $CHAIN"
    else
      `sed -i "/$ID/d" $RULE_PATH/$RULE_FILE`
      CHECK_FILE_DAEMON_RULE_RESULT=`check_file_daemon_rule`
      if [ $CHECK_FILE_DAEMON_RULE_RESULT -eq 0 ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "Delete Line All $ID $CHAIN"
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" "$RULE_PATH/$RULE_FILE" "Delete Line All $ID $CHAIN"
          exit 1
      fi
  fi
}

add_iptables()
{
  CHECK_RULE_RESULT=`check_rule`

  if [ $CHECK_RULE_RESULT -eq 0 ]
    then
      RULE_INSERT_INDEX=`get_rule_index`
      ADD_RULE="iptables -I $CHAIN $RULE_INSERT_INDEX $IP_OPTION -p $PORT_TYPE --$PORT_DIRECTION $PORT_NUM -j $POLICY"
      `$ADD_RULE`
      CHECK_RULE_RESULT=`check_rule`
      if [ $CHECK_RULE_RESULT -eq 1 ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" "iptables" "$ADD_RULE"
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" "iptables" "$ADD_RULE"
      fi
    else
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[36mSKIP\033[0m ]\n" "iptables" "$ADD_RULE"
  fi
}

del_iptables()
{
  CHECK_RULE_RESULT=`check_rule`
  if [ $CHECK_RULE_RESULT -eq 0 ]
    then
      printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[36mSKIP\033[0m ]\n" "iptables" "$CMD $CHAIN $IP_OPTION $PORT_TYPE $PORT_NUM $POLICY"
    else
      DEL_RULE="iptables -D $CHAIN $IP_OPTION -p $PORT_TYPE --$PORT_DIRECTION $PORT_NUM -j $POLICY"
      `$DEL_RULE 2> /dev/null`
      CHECK_RULE_RESULT=`check_rule`
      if [ $CHECK_RULE_RESULT -eq 0 ]
        then
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" "iptables" "$DEL_RULE"
        else
          printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[31mFAIL\033[0m ]\n" "iptables" "$DEL_RULE"
          exit 1
      fi
  fi
}

del_iptables_all()
{
  if [ -f $RULE_PATH/$RULE_FILE ]
    then
      while read RULE
        do
          RULE_LINE=`echo $RULE |grep "$ID"`
          if [ -n "$RULE_LINE" ]
            then
             DEL_RULE=`echo $RULE_LINE |sed -e "s%-I%-D%g" -e "s%#.*$%%"` 
             `$DEL_RULE 2> /dev/null`
              printf >&2 "[ \033[33m%-39s\033[0m ] %-40s [ \033[32mOK\033[0m ]\n" "iptables" "$DEL_RULE"
          fi
      done < $RULE_PATH/$RULE_FILE
  fi
}

rule_main()
{
  check_chain

  if [ $CMD == "add" ]
    then
      add_iptables
      add_iptables_file
  elif [ $CMD == "del" ]
    then
      del_iptables
      del_iptables_file
  elif [ $CMD == "del_all" ]
    then
      del_iptables_all
      del_iptables_file_all
  fi
}

rule_main
exit 0
