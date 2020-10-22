#!/bin/sh

Make_Directory () {
  echo "mkdir STARTING..."
  echo "port range: $1 ~ $2"
  for ((i=$1, idx=1; i<=$2 ; i++, idx++))
    do  
      sleep 0.05
     mkdir test_$idx;
     echo "makedir test_$idx"
    done

    sleep 1
}


Remove_Directory () {
    echo "Delete : all  directory"  
 # for ((i=$1, idx=1; i<=$2 ; i++, idx++))
  #  do  
   #   sleep 0.05
    rm -r  test_*
     echo "remove all test"
 #   done


}


Make_or_Remove() {
  echo "tcp port range : 10001 ~ 10100"
    while true
      do  
        echo -n "Enter make(m) or remove(r): "
          read x
          case "$x" in
          m | make ) return 0;; 
      r | remove ) return 1;; 
      * ) echo "Answer start or end"
        esac
        done
}


echo "SIMULATOR Shell [snmp-agent]"
if Make_or_Remove
then
  #echo "(YES) starting..."
  #simulator_start 10240 10250 # for testing
  Make_Directory 1 100
else
  #echo "(NO) stopng..."
  Remove_Directory 
fi
exit 0

