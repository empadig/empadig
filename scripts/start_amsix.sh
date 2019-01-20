#!/bin/bash

# inputs
start_timestamp=`date -d "2015-05-12 10:00:00" "+%s"`
end_timestamp=`date -d "2015-05-14 10:00:00" "+%s"`
esp="amsix"
db_name="${esp}_traceroutes"

#measurments id
msms="1769335 1790203 1026399 1042245 1402317 1765882"


#set to yes/no to execute or not
download="yes"
insertdb="yes"
#computation is always performed at the end

source common.sh
