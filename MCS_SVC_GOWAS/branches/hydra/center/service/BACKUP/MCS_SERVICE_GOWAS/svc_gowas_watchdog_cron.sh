#!/bin/sh

# ######################################################### #
# Section 1 (Binary Path)                                   #
# ######################################################### #
PATH=/usr/bin:/usr/local/bin:/bin:/usr/bin:.
export PATH

# ######################################################### #
# Section 2 (Deamon monitor shell Path)                     #
# ######################################################### #
DEAMON_WATCHDOG_SHELL_PATH="/home/kwgwak77/SVCgoWAS_TEST/MCS_SERVICE_GOWAS"
DEAMON_WATCHDOG_SHELL="svc_gowas_watchdog.sh"

# ######################################################### #
# Customizing Section 3 (Cron watchdog Log)                 #
# ######################################################### #
cron_log_dir="$DEAMON_WATCHDOG_SHELL_PATH/watchdog_log"
cron_logfile=$cron_log_dir"/watchdog_cron.log"

if [[ ! -e $cron_log_dir ]]; then
  mkdir $log_dir
fi
# kill the named process(es)
killproc() {
  for x in "$@";do
    pid=`ps -e |grep "$x" |sed -e 's/^  *//' -e 's/ .*//'`
      [ ! -z "$pid" ] && echo killing $x && kill $pid &
      done
}

# return pid of the named process(es)
findproc() {
  pid=`ps -e | grep -v grep | grep "$1" |sed -e 's/^  *//' -e 's/ .*//'`
    echo $pid
}

# return pid of the named process(es)
findmon() {           
  pid=`ps -ef | grep -v grep | grep "$DEAMON_WATCHDOG_SHELL" | awk '{print $2}'`
    echo $pid
}


# ############################################################################################################### #
#   Check deamon_monitor.sh process status                                                                        #
# ############################################################################################################### #
pid=`findmon`

if [ -n "$pid" ]; then
echo `date +"%Y/%m/%d %H:%M:%S"` "$DEAMON_WATCHDOG_SHELL already started !!" > /dev/null
else
echo `date +"%Y/%m/%d %H:%M:%S"` "$DEAMON_WATCHDOG_SHELL stopped !!" >> $cron_logfile
echo `date +"%Y/%m/%d %H:%M:%S"` "$DEAMON_WATCHDOG_SHELL will be restarted !!" >> $cron_logfile
cd $DEAMON_WATCHDOG_SHELL_PATH
./$DEAMON_WATCHDOG_SHELL &
fi

