#!/usr/bin/python
# This script takes as input a json file (which is ana array)
# and produces in output a bson file containing all the objects of the file, one each line.
import glob
import json
import sys

file_name = sys.argv[1]

output = open('output.bson', 'w')

print "Loading %s" % file_name
with open(file_name) as json_file:
    data = json.load(json_file)
    for trace in data:
        output.write(json.dumps(trace) + "\n")
    print "%s objects processed" % str(len(data))
output.close()
