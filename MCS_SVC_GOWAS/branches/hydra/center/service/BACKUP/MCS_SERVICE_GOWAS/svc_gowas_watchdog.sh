#!/bin/sh 

# ######################################################### #
# Section 1 (Binary Path)                                   #
# ######################################################### #
PATH=/usr/bin:/usr/local/bin:/bin:/usr/bin:.
export PATH

# ######################################################### #
# Section 2 (LD Path)                                       #
# ######################################################### #
#LD_LIBRARY_PATH=/home/developer/test/lib/
#export LD_LIBRARY_PATH

# ######################################################### #
# Section 3 (Deamon Path)                                   #
# ######################################################### #
HOST_NAME=`hostname`

# -- (1/5 Binary Full Path) ------ #
DEAMON_EXE_PATH="/home/kwgwak77/SVCgoWAS_TEST/MCS_SERVICE_GOWAS"
# -------------------------------- #

# -- (2/5 WatchDog Log Path) ----- #
log_dir="$DEAMON_EXE_PATH/watchdog_log"
logfile=$log_dir"/status.`date +"%Y%m"`"

if [[ ! -e $log_dir ]]; then
  mkdir $log_dir
fi
# -------------------------------- #

# -- (3/5 Watch Dog Log Path) ---- #
core_limit_counter=3
# -------------------------------- #

echo `env` >> $logfile

checksingleproc() {
  PROC=`echo $1 | awk '{ if(length($1) > 15) print substr($1,0,15); else print $1; }'`
  pid=`ps -e | grep "$PROC" | sed -e 's/^  *//' -e 's/ .*//'`

  if [ -n "$pid" ]; then
    echo `date +"%Y%m%d-%H%M%S"` > /dev/null
  else
    echo `date +"%Y%m%d-%H%M%S"` "$1 start!!" >> $logfile

    
    # --(4/5 Relative path movement)-- #
    cd $DEAMON_EXE_PATH
    # -------------------------------- #

    core_count=`find . -name "core.*" -type f | wc -l`
    # --(5/5 Execute Option)---------- #
    if (( $core_count >= $core_limit_counter )); then
      ulimit -c 0
      ulimit -n 5005
      ./$1 -l 9090 -p bg
    else
      ulimit -c unlimited
      ulimit -n 5005
      GOTRACEBACK=crash ./$1 -l 9090 -p bg
    fi
    # -------------------------------- #
  fi
}

while [ 1 ]
do
  # ######################################################### #
  # Customizing Section 4-1 (single process name)             #
  # ######################################################### #
  checksingleproc innogs_gowas

  sleep 5
done


