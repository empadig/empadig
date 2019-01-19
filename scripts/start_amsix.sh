#!/bin/bash

# inputs
start_timestamp=`date -d "2015-05-12 10:00:00" "+%s"`
end_timestamp=`date -d "2015-05-14 10:00:00" "+%s"`
esp="amsix"
db_name="${esp}_traceroutes"

#measurments id
msms="1769335 1790203 1026399 1042245 1402317 1765882"


#set to yes/no to execute or not
download="no"
insertdb="no"
#computation is always performed at the end


if [ "$download" = "yes" ]; then
for msm_id in $msms; do
    filename=${esp}"_"$msm_id"_from_"$start_timestamp"_to_"$end_timestamp
    # download, but do not re-downlaod
    url="https://atlas.ripe.net/api/v2/measurements"
    wget  -nc $url/$msm_id"/results?start="$start_timestamp"&stop="$end_timestamp"&format=json" -O $filename".json"
done
fi

if [ "$insertdb" = "yes" ]; then
# remove db if it exists
mongo $db_name --eval "printjson(db.dropDatabase())"

# Create db and indexes
mongo $db_name --eval "
db['traceroute'].ensureIndex({'prb_id': 1});
db['traceroute'].ensureIndex({'msm_id':1, 'prb_id':1});
db['traceroute'].ensureIndex({'startTimestamp': 1});
db['ip2as'].ensureIndex({ 'address': 1 }, { unique: true });
db['probe-metadata'].ensureIndex({ 'prb_id': 1 }, { unique: true });
db['measurement'].ensureIndex({ 'msm_id': 1 }, { unique: true });
"


for msm_id in $msms; do
    filename=${esp}"_"$msm_id"_from_"$start_timestamp"_to_"$end_timestamp

    # print data in bson
    python make_bson.py $filename".json";
    mv output.bson $filename".bson";

    # convert data in empadig format
    node atlas2tplay.js $filename".bson" GeoIPASNum.csv
    # New files
    # traceroute.bson
    # measurement.bson
    # ip2as.bson
    # probe-metadata.bson
    # probe_cache.json

    mongoimport --db $db_name --collection measurement < measurement.bson
    mongoimport --db $db_name --collection ip2as < ip2as.bson
    mongoimport --db $db_name --collection probe-metadata < probe-metadata.bson
    mongoimport --db $db_name --collection traceroute < traceroute.bson

    rm $filename".bson"
    rm traceroute.bson
    rm measurement.bson
    rm ip2as.bson
    rm probe-metadata.bson
    rm probe_cache.json
done
fi

period=`date -d @$start_timestamp +%Y%m%d%H%M%S`-`date -d @$end_timestamp +%Y%m%d%H%M%S`

# Run load-balancing inference heuristic
time python ../algorithm/empadig.py --period $period --db $db_name lbsets --save ./${esp}-$period".lb" > /dev/null

# Run empadig considering inferred load balancers
time python ../algorithm/empadig.py --period $period --db $db_name great_analysis --nowildcards --load ./${esp}-$period".lb" --threshold 1 --json > /dev/null
mv output.json ${esp}-events-with-lb-heuristic.json

# Run empadig without heuristic
time python ../algorithm/empadig.py --period $period --db $db_name great_analysis --nowildcards --threshold 1 --json > /dev/null
mv output.json ${esp}-events-without-lb-heuristic.json

# Make impact data (with heuristic)
python make_impact_data.py --file_name=${esp}-events-with-lb-heuristic.json --db_name=$db_name> ${esp}-impact-data-with-lb-heuristic.dat

# Make impact data (without heuristic)
python make_impact_data.py --file_name=${esp}-events-without-lb-heuristic.json --db_name=$db_name> ${esp}-impact-data-without-lb-heuristic.dat

# plot events (with heuristic)
./plot_events.sh ${esp}-impact-data-with-lb-heuristic.dat ${esp}-events-impact-with-lb-heuristic.png

# plot events (without heuristic)
./plot_events.sh ${esp}-impact-data-without-lb-heuristic.dat ${esp}-events-impact-without-lb-heuristic.png

# Generate summary events
python sort_events.py ${esp}-events-without-lb-heuristic.json 20 | python -m json.tool >> ${esp}-events-impact-without-lb-heuristic-top20.json
python sort_events.py ${esp}-events-with-lb-heuristic.json 20 | python -m json.tool >> ${esp}-events-impact-with-lb-heuristic-top20.json


# Clean-up
#rm $filename".json"
#rm ./$period".lb"
#rm impact-data-with-lb-heuristic.dat
#rm impact-data-without-lb-heuristic.dat
