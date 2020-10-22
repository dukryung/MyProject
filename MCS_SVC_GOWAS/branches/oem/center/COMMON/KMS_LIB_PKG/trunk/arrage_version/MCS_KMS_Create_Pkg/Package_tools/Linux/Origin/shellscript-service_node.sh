#!/bin/bash


ARGC=$#
CUR_PATH=$PWD
SOURCE_TEMP_PATH=$CUR_PATH
SOURCE_FILE_USERKEY_PATH=$SOURCE_TEMP_PATH/userkey.key
SOURCE_FILE_CFG_PATH=$SOURCE_TEMP_PATH/svc_corporation/cfg


mv  $SOURCE_FILE_USERKEY_PATH $SOURCE_FILE_CFG_PATH 
mv  ./svc_node ./svc_corporation

tar -zcvf svc_node.tar.gz ./svc_corporation
mv $SOURCE_TEMP_PATH/svc_node.tar.gz ../
#rm -rf ./svc_corporation

exit 0
