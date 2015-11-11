#!/usr/bin/python

import json
import sys

# sys.argv[1] = The json file
# sys.argv[2] = The number of events to show. (example: 10 will show the first 10 events sorted by len("sd_pairs"))


file_name = sys.argv[1]


with open(file_name) as f:
    data = json.load(f)

all_events = data["events"]
all_events.sort(lambda a, b: len(a["sd_pairs"]) - len(b["sd_pairs"]), reverse=True)

essentials = map(lambda e: {"ips": e["ips"], "impact": len(e["sd_pairs"])}, all_events)
print json.dumps(essentials[0:int(sys.argv[2])])
