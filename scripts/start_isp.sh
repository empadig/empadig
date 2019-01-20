#!/bin/bash

20140502000000-20140503235959
# inputs
start_timestamp=`date -d "2014-05-02 00:00:00" "+%s"`
end_timestamp=`date -d "2014-05-13 23:59:59" "+%s"`
esp="isp"
db_name="${esp}_traceroutes"

#measurments id
msms="1663314"


#set to yes/no to execute or not
download="yes"
insertdb="yes"
#computation is always performed at the end

source common.sh
