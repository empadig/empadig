#!/usr/bin/python

import json
import sys
import time, calendar
import random
from ip2as import Ip2As


def get_event_type(event):
    event_type = "unknown"
    if all([ip[1] == "pre" for ip in event["ips"]]):
        event_type = "down"
    if all([ip[1] == "post" for ip in event["ips"]]):
        event_type = "up"
    return event_type


def sort_by_address(labeled_ips):
    return sorted(labeled_ips, key=lambda ip: ip[0])


def format_labeled_ip(ip):
    return "%s%s" % (ip[0], "-" if ip[1] == "pre" else "+")


file_name = sys.argv[1]
color_type = sys.argv[2] if len(sys.argv) >= 3 else "color_by_ip"
if color_type not in ["color_by_ip", "color_by_type"]:
    raise Exception("Unknown coloring: %s" % color_type)

with open(file_name) as f:
    data = json.load(f)

all_events = data["events"]
all_events.sort(lambda a, b: a["start"] - b["start"])

random.seed("colors") 

# Map a sequence of plain IPs (e.g. 1.1.1.1,2.2.2.2) to a random color
ips2color = {}

# Compute colors for the ips2color map
for event in all_events:
    ips = sort_by_address(event["ips"])
    fips = ",".join([ip[0] for ip in ips])
    if fips not in ips2color:
        ips2color[fips] = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

fmt = "%Y-%m-%d %H:%M:%S"
ip2as = Ip2As()

print "# start_date\tend_date\tavg_date\timpact\tr\tg\tb\tips\tlen(ips)\tasns\tholders"
for event in all_events:
    avg_timestamp = event["start"] + (event["end"] - event["start"]) / 2
    ips = sort_by_address(event["ips"])
    asns = []
    holders = []
    for ip in ips:
        asn, holder = ip2as.get(ip[0])
        asns.append(asn)
        holders.append(holder)
    # The sequence of plain IPs in this event
    fips = ",".join([ip[0] for ip in ips])
    # The sequence of extended IPs in this event
    flips = ",".join([format_labeled_ip(ip) for ip in ips])
    # Decide the color of this event
    if color_type == "color_by_ip":
        red, green, blue = ips2color[fips]
    if color_type == "color_by_type":
        event_type = get_event_type(event)
        if event_type == "down":
            red, green, blue = 255, 0, 0
        elif event_type == "up":
            red, green, blue = 0, 0, 255
        else:
            red, green, blue = 255, 255, 0
    print "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%d\t%s\t%s" %  (
            time.strftime(fmt, time.gmtime(event["start"])),
            time.strftime(fmt, time.gmtime(event["end"])),
            time.strftime(fmt, time.gmtime(avg_timestamp)),
            len(event["sd_pairs"]),
            red,
            green,
            blue,
            flips,
            len(ips),
            ",".join([str(asn) for asn in asns]),
            ",".join([str(holder) for holder in holders])
    )
