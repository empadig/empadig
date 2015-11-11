#!/bin/bash

# inputs
start_timestamp=`date -d "2015-03-26 09:30:00" "+%s"`
end_timestamp=`date -d "2015-03-28 09:30:00" "+%s"`
msm_id=1042245
db_name="test_db"

# extrapolate period from inputs
period=`date -d @$start_timestamp +%Y%m%d%H%M%S`-`date -d @$end_timestamp +%Y%m%d%H%M%S`

# download data from RIPE Atlas
filename=$msm_id"_from_"$start_timestamp"_to_"$end_timestamp
url="https://atlas.ripe.net/api/v2/measurements"
wget $url/$msm_id"/results?start="$start_timestamp"&stop="$end_timestamp"&format=json" -O $filename".json"

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

# Create db and indexes
mongo $db_name --eval "
db['traceroute'].ensureIndex({'prb_id': 1});
db['traceroute'].ensureIndex({'msm_id':1, 'prb_id':1});
db['traceroute'].ensureIndex({'startTimestamp': 1});
db['ip2as'].ensureIndex({ 'address': 1 }, { unique: true });
db['probe-metadata'].ensureIndex({ 'prb_id': 1 }, { unique: true });
db['measurement'].ensureIndex({ 'msm_id': 1 }, { unique: true });
"


mongoimport --db $db_name --collection measurement < measurement.bson
mongoimport --db $db_name --collection ip2as < ip2as.bson
mongoimport --db $db_name --collection probe-metadata < probe-metadata.bson
mongoimport --db $db_name --collection traceroute < traceroute.bson

# Run load-balancing Heuristic
time python ../algorithm/empadig.py --period $period --db $db_name lbsets --save ./$period".lb" > /dev/null

# Run empadig with heuristic
time python ../algorithm/empadig.py --period $period --db $db_name great_analysis --nowildcards --load ./$period".lb" --threshold 1 --json > /dev/null
mv output.json events-with-lb-heuristic.json

# Run empadig without heuristic
time python ../algorithm/empadig.py --period $period --db $db_name great_analysis --nowildcards --threshold 1 --json > /dev/null
mv output.json events-without-lb-heuristic.json

# Make impact data (with heuristic)
python make_impact_data.py events-with-lb-heuristic.json > impact-data-with-lb-heuristic.dat

# Make impact data (without heuristic)
python make_impact_data.py events-without-lb-heuristic.json > impact-data-without-lb-heuristic.dat

# plot events (with heuristic)
./plot_events.sh impact-data-with-lb-heuristic.dat events-impact-with-lb-heuristic.png

# plot events (without heuristic)
./plot_events.sh impact-data-without-lb-heuristic.dat events-impact-without-lb-heuristic.png

# Generate summary events
python sort_events.py output-without-lb-heuristic.json 20 | python -m json.tool >> events-impact-without-lb-heuristic-top20.json
python sort_events.py output-with-lb-heuristic.json 20 | python -m json.tool >> events-impact-with-lb-heuristic-top20.json


# Clean-up
rm $filename".json"
rm $filename".bson"
rm measurement.bson
rm ip2as.bson
rm probe-metadata.bson
rm traceroute.bson
rm probe_cache.json
rm ./$period".lb"
rm impact-data-with-lb-heuristic.dat
rm impact-data-without-lb-heuristic.dat
