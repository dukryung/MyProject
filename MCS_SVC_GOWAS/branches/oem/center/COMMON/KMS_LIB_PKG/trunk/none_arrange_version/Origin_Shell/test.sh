#!/bin/bash

ARGC=$#
CUR_PATH=$PWD
SOURCE_ORIGINAL_PATH=/root/go/src/MCS_KMS_Create_Pkg/Origin
SOURCE_ORIGINAL_CFG_PATH=$CUR_PATH/lbsvc/etc/init.d/cfg
SOURCE_TEMP_PATH=$CUR_PATH/lnx_Temp


echo $CUR_PATH
echo $SOURCE_ORIGINAL_PATH
echo $SOURCE_ORIGINAL_CFG_PATH
echo $SOURCE_TEMP_PATH

cp -r $SOURCE_ORIGINAL_PATH/MCSE_Origin/lbsvc $CUR_PATH
mv  $SOURCE_TEMP_PATH/userkey.txt $SOURCE_ORIGINAL_CFG_PATH 
tar -zcvf $CUR_PATH/Package.tar.gz ./lbsvc
rm -rf ./lbsvc


exit 0
