#!/usr/bin/python

import sys
import time, calendar
from datetime import datetime
from datetime import timedelta
import argparse
import random
import math
import json
import correlation_graph_analysis
from pprint import pprint
from pymongo import *
from sortedcollection import SortedCollection
import networkx
import networkx.algorithms.approximation
#import pygraphviz
from sortedcontainers import SortedSet

from collections import namedtuple

CandidateEvent = namedtuple("CandidateEvent", "start end ip sdpairs")

fmt="%Y-%m-%d %H:%M:%S"

def log(s, sameline=False):
    if sameline:
        sys.stderr.write(s)
    else:
        sys.stderr.write(s+'\n')
    sys.stderr.flush()


def print_timestamps(m,p):
    cursor=(tr.find( {"prb_id": p, "msm_id":m}, {"startTimestamp":1} )
               .sort("startTimestamp", ASCENDING)
            )
    i=cursor.next()
    prev=i["startTimestamp"]
    print time.strftime(fmt, time.gmtime(prev))
    for i in cursor:
        next=i["startTimestamp"]
        print next-prev
        print " "*8,time.strftime(fmt, time.gmtime(next))
        prev=next

def find_probes():
    for i in tr.distinct( "prb_id" ):
        for AS in db["probe-metadata"].find({"prb_id": i}, {"v4_as":1, "v4_as_holder":1}):
            print AS["v4_as"], i,  AS['v4_as_holder']


def massive():
    z=0
    n=0
    for i in tr.find( {}, {"startTimestamp":1}):
        n+=1
        if (n%10000) == 1:
            print n
        z+=i["startTimestamp"]

    print z



def find_msmid():
    for i in tr.distinct( "msm_id" ):
        print i

def find_prb_msm_pairs():
    msm=set()
    for i in tr.distinct( "msm_id" ):
        msm.add(i)

    for m in msm:
        probes=db.command( { "distinct":"traceroute", "key": "prb_id", "query":{ "msm_id": m } } )["values"]
        for p in probes:
            print m, p


def find_prb_dest_pairs_for_AS(AS):
    """AS is an integer which represents the AS number in the ipv4 realm. Returns all 
    destination probe pairs for probes in the specified AS"""
    r=set()
    meta=db['probe-metadata']
    probesOfAs=meta.find({'v4_as': AS}, {'prb_id':1})
    for pobj in probesOfAs:
        p=pobj['prb_id']
        destinations= db.command( { "distinct":"traceroute", "key": "msm_id", "query":{ "prb_id": p } } )["values"]
        for d in destinations:
            r.add( (d,p) )
    return r

def find_prb_dest_pairs_all(): 
    """Returns all destination probe pairs in the DB, possibly sampled by args.num_sdpairs and args.randmo_seed"""
    log('finding source destination pairs')

    sd_pairs = set()
    #probes = [ p for p in  tr.find({}, {'prb_id':1, 'msm_id':1}).distinct('prb_id') ]
    cursor = tr.find({}, {'prb_id':1, 'msm_id':1})
    #cursor = tr.find({"startTimestamp":{"$gte":tmin, "$lte":tmax}}, {'prb_id':1, 'msm_id':1})
    
    for x in cursor:
        p = x['prb_id']
        d = x['msm_id']
        if (d, p) in sd_pairs:
            continue
        sd_pairs.add((d, p))

    log('Found %s unique sd-pairs' % len(sd_pairs))
    
#     cursor = db['probe-metadata'].find({}, {'prb_id':1})
#     probes = [probe['prb_id'] for probe in cursor]
#     for p in probes:
#         destinations = db.command({"distinct": "traceroute", "key": "msm_id", "query": {"prb_id": p}})["values"]
#         for d in destinations:
#             sd_pairs.add((d, p))
    if args.__dict__["num_sdpairs"] and args.__dict__["random_seed"]:
        lsd_pairs = list(sd_pairs)
        lsd_pairs.sort()
        random.seed(args.random_seed)
        random.shuffle(lsd_pairs)
        selected_sd_pairs = lsd_pairs[:min(args.num_sdpairs, len(lsd_pairs))]
        # In case you want to check the order of sd-pairs
        #with open("random_pairs.txt", "a") as f:
        #    f.write("%s,\n" % json.dumps(selected_sd_pairs))
        sd_pairs = set(selected_sd_pairs)
    return sd_pairs



def count_prb_msm_pairs():
    for line in file("pairs.txt"):
        msm,probe=line.split()
        c=tr.find({"msm_id":int(msm), "prb_id":int(probe)}).count()
       

def find_one():
    pprint(tr.find_one())



def find_lasthop():
    probes={}
    for i in tr.find({}, {"prb_id":1 , "msm_id": 1, "hops.replies.ip": 1, "_id":0}).limit(100000):
        probe=i["prb_id"]
        measurement=i["msm_id"]
        m=(probe, measurement)
        h=i["hops"]
        if len(h)==0: continue
        last=h[-1]["replies"]
        if len(last)==0: continue
        if not probes.has_key(m):
            probes[m]=set()
        probes[m].add(last[0]["ip"])
    for pr, m in probes.keys():
        for trgt in probes[(pr,m)]:
            print trgt, pr, m


def count_one_history(m, p):
    print tr.find({"prb_id": p, "msm_id": m}, {"hops": 1, "startTimestamp":1, "_id":0}).count()


def report_AS_history(AS):
    meta=db['probe-metadata']
    probesOfAs=meta.find({'v4_as': AS}, {'prb_id':1})
    for pobj in probesOfAs:
        p=pobj['prb_id']
        #destinations= tr.find({'prb_id':p}, {'msm_id':1})
        destinations= db.command( { "distinct":"traceroute", "key": "msm_id", "query":{ "prb_id": p } } )["values"]
        for d in destinations:
            c=tr.find({"prb_id": p, "msm_id": d}, {"hops": 1, "startTimestamp":1, "_id":0}).count()
            print d, p, c





def one_history(m, p):
    for i in tr.find({"prb_id": p, "msm_id": m}, {"hops": 1, "startTimestamp":1, "_id":0}).sort("startTimestamp").limit(1000):
        pprint(i)


def one_history_hint(m, p):
    cursor=(tr.find({"prb_id": p, "msm_id": m}, {"hops": 1, "startTimestamp":1, "_id":0}).sort("startTimestamp")
             .hint( [(u'msm_id', ASCENDING),
                     (u'startTimestamp', ASCENDING),
                     (u'prb_id', ASCENDING)]
                   )
             )
    for i in cursor:
        pprint(i)




def indexes():
    pprint(tr.index_information())

def explain_history_query(m, p):
    pprint(tr.find({"prb_id": p, "msm_id": m}, {"hops": 1, "startTimestamp":1, "_id":0}).explain())

def explain_hint_history_query(m, p):
    pprint(tr.find({"prb_id": p, "msm_id": m}, {"hops": 1, "startTimestamp":1, "_id":0})
             .hint( [(u'msm_id', ASCENDING),
                     (u'startTimestamp', ASCENDING),
                     (u'prb_id', ASCENDING)]
                   )
             .explain()
           )

def one_history_hint2(m, p):
    cursor=(tr.find({"prb_id": p, "msm_id": m}, {"hops": 1, "startTimestamp":1, "_id":0}).sort("startTimestamp")
             .hint( [(u'msm_id', ASCENDING),
                     (u'startTimestamp', ASCENDING),
                     (u'prb_id', ASCENDING)]
                   )
             )
    for i in cursor:
        h=i["hops"]
        try:
            last=h[-1]["replies"][0]
        except IndexError:
            print len(h), i["startTimestamp"], "*"
            continue

        print len(h), i["startTimestamp"], last["ip"], last["rtt"][0]


def select_interval(m, p, tmin, tmax):
    cursor=(tr.find({"prb_id": p, "msm_id": m, "startTimestamp": {"$gte":tmin, "$lte": tmax } }, {"hops": 1, "startTimestamp":1, "_id":0}).sort("startTimestamp")
             .hint( [(u'msm_id', ASCENDING),
                     (u'startTimestamp', ASCENDING),
                     (u'prb_id', ASCENDING)]
                   )
             )

    for i in cursor:
        pprint(i)

 
# ==== Eqset                                                                                                         

class EqSet:

    def __init__(self):
        self.elements={}  # map each element (string) to a set (integer)
        self.sets={}  # map each set (integer) to its set of elements (string)
        self.setidnext=1
        self.representatives=None

    def computeRepresentatives(self):
        assert not self.representatives
        self.representatives={}
        for s in self.sets:
            q=self.sets[s]
            L=list(q)
            L.sort()
            r=L[0]
            self.representatives[s]=r

    def _newEmptySet(self):
        cid=self.setidnext
        self.setidnext+=1
        self.sets[cid]=set()
        return cid

    def mergeSets(self, s1, s2):
        "s1 and s2 are represented by integers. Post: s1 contains all elements of s2, s2 is deleted."
        #import pdb; pdb.set_trace()
        for e in self.sets[s2]:
            self.sets[s1].add(e)
            self.elements[e]=s1
        del self.sets[s2]

    def add(self, s):
        """s is a python set of elements. 
        Postcondition: all elements in s are in the same set as well as all elements of sets that was already 
        there and share some elements with s, that is all sets covered by s are merged."""
        assert not self.representatives
        if len(s)==0:
            return
        setOfCoveredSets=set() #identified by integer
        newElements=set()
        for i in s:
            if self.elements.has_key(i):
                q=self.elements[i] # the covered set
                setOfCoveredSets.add(q)
            else:
                newElements.add(i)

        dest=None
        for currset in setOfCoveredSets:
            if dest == None:
                dest=currset
            else:
                self.mergeSets(dest, currset)
        if dest == None:
            dest=self._newEmptySet()
        for i in newElements:
            self.sets[dest].add(i)
            self.elements[i]=dest

    def getsets(self):
        return self.sets.values()

    def getmapping(self):
        r={}
        for idx, s in self.sets.iteritems():
            representative=self.representatives[idx]
            r[representative]=s
        return r

    def getrepr(self, e):
        try:
            s=self.elements[e]
        except:
            return e
        return self.representatives[s]+"*"

    def __str__(self):
        r=""
        for k, v in self.sets.viewitems():
            r+=str(self.representatives[k])+":"
            r+="{"
            for i in v:
                r+=str(i)+", "
            r=r[:-2]  # strip off last coma
            r+="}\n"
        return r

    def save(self, stream):
        import pickle
        assert self.representatives
        tosave={'sets':self.sets,
                'elements': self.elements,
                'representatives': self.representatives
                }

        pickle.Pickler(stream).dump(tosave)
        stream.close()

    @staticmethod
    def load(stream):
        log("loading load balancer file: " + str(stream))
        import pickle
        loaded=pickle.Unpickler(stream).load()
        log("loaded.")
        e=EqSet()
        e.sets=loaded['sets']
        e.elements=loaded['elements']
        e.representatives=loaded['representatives']
        e.setidnext= max(e.sets.keys())+1
        stream.close()
        return e

#----------------------------------------------------
#class TrEventNoPath:
    #def __init__(when):
        #self.when=when


#class TrEventPathChange:
    #def __init__(timestamp, from, to):
        #self.when=when
        #self.from=from # array of ip addresses represented as string
        #self.to=to


class PathDelta:
    "Difference between two paths of a traceroute"
    def __str__(self):
        return "%d %s %s %d" % (self.distance, self.frm, self.to, self.pos)
    # fullpathfrom
    # fullpathto
    # pathfrom
    # pathto
    # pos
    # distance (len(from)+len(to))
    # lengthfrom
    # lenghtto

class TrEvent(PathDelta):
    "event in the tracerout history from specified source to target"
    # prb_id
    # msm_id
    # from_timestamp
    # to_timestamp

    def __init__( self, pd, pid, mid, fts, tts, frtt, trtt):
        self.fullpathfrom=pd.fullpathfrom
        self.fullpathto=pd.fullpathto
        self.pathfrom=pd.pathfrom
        self.pathto=pd.pathto
        self.pos=pd.pos
        self.lengthfrom=pd.lengthfrom
        self.lengthto=pd.lengthto
        self.distance=pd.distance
        self.msm_id=mid
        self.prb_id=pid
        self.from_timestamp=fts
        self.to_timestamp=tts
        self.from_rtt= frtt
        self.to_rtt= trtt

    def __str__(self):
        return "%d %s %s %d %s %s %d %d" % (self.distance, self.pathfrom, self.pathto, self.pos, self.prb_id, self.msm_id, self.from_timestamp, self.to_timestamp)

    def fwdhash(self):
        import md5
        return md5.new(repr(self.pathfrom)+repr(self.pathto)).hexdigest()

    def rvshash(self):
        import md5
        return md5.new(repr(self.pathto)+repr(self.pathfrom)).hexdigest()

    def dictRepr(self):
        fh=self.fwdhash()
        rh=self.rvshash()
        rttmid= (self.to_rtt+self.from_rtt)/2
        rttbvar= (self.to_rtt-self.from_rtt)/rttmid  # baricentric variation
        return {
                "prb_id": self.prb_id,
                "msm_id": self.msm_id,
                "pathpos": self.pos,
                "path_prev": self.pathfrom,
                "path_next": self.pathto,
                "path_dist": self.distance,
                "hash_fwd": fh,
                "hash_rvs": rh,
                "ts_prev": self.from_timestamp,
                "ts_next": self.to_timestamp,
                "rtt_prev": self.from_rtt,
                "rtt_next" : self.to_rtt,
                "rtt_bvar" : rttbvar,
                "rtt_absbvar" : abs(rttbvar)

                }



class TrDistilled:
    def __str__(self):
        rtt= self.rtt if self.rtt != None else "None"
        return "%d %s %d %s" % (self.timestamp, rtt, self.len, self.path)
    #timestamp
    #path
    #rtt
    #len

def extract(json, eqset):
    """take a json in the TPlay format in the mongo db and extract relevant fields for analysis"""

    trhops=[]
    for i in json["hops"]:
        if i["noAnswer"]:
            trhops.append("*")
        else:
            ip=i["replies"][0]["ip"]
            if eqset:
                ip=eqset.getrepr(ip)
            trhops.append(ip)

    try:
        rtt = json["hops"][-1]["replies"][0]["rtt"][0]
    except:
        rtt = None
    length=len(json["hops"])

    result=TrDistilled()
    result.timestamp=json["startTimestamp"]
    result.path=trhops
    result.rtt=rtt
    result.len=length
    return result


# ==== delta                                                                                          

def comparePaths(p1,p2):
    """
    Compare two paths (array of strings).
    """

    # strip all leading '*'
    for p in [p1,p2]:
        while len(p)>0 and p[-1]=='*':
            p=p[:-1]

    maxhead=min(len(p1)-1,len(p2)-1)

    head=0 #increasing, 0 means the first element
    tail=-1 #decresing, -1 means "the last element", -2 "the one before the last element"

    while True:


        if head >= maxhead+1:  # head after end of the shortest path among the two
            break
        if not (tail >= -(len(p1)-head) and tail >= -(len(p2)-head)): # tail before head
            break

        if p1[head]==p2[head]!="*":
            head+=1
            continue
        if p1[tail]==p2[tail]!="*":
            tail-=1
            continue
        if p1[head]=="*" or p2[head]=="*":
            head+=1
            continue
        if p1[tail]=="*" or p2[tail]=="*":
            tail-=1
            continue

        break # mismatch on both head and tail

    # now head points to the first position that has no matching 
    # or after the last position of the shortest between p1 and p2

    # now tail points (starting from the end) to the first position that has no matching 
    # or to the head in the shortest between p1 and p2

    d=PathDelta()
    d.pos=head
    d.fullpathfrom=p1
    d.pathfrom=p1[head:len(p1)+tail+1]
    d.fullpathto=p2
    d.pathto=p2[head:len(p2)+tail+1]
    d.distance=len(d.pathfrom)+len(d.pathto)
    d.lengthfrom=len(p1)
    d.lengthto=len(p2)
    return d



#--------------------------
def compareTr_null1_test():
    p1=[ "1", "2", "3" ]
    p2=[ ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[ "1", "2", "3" ]
    assert d2==[]

def compareTr_null2_test():
    p1=[  ]
    p2=[ "1", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[  ]
    assert d2==["1", "2", "3" ]

def compareTr_null3_test():
    p1=[  ]
    p2=[ "1" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[  ]
    assert d2==["1"]

def compareTr_null4_test():
    p1=[ "1"  ]
    p2=[ ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[  "1"]
    assert d2==[]

def compareTr_null5_test():
    p1=[ ]
    p2=[ ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[]
    assert d2==[]


def compareTr_equal1_test():
    p1=[ "1", "2", "3" ]
    p2=[ "1", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==[]
    assert d2==[]

def compareTr_equal2_test():
    p1=[ "1", "2", "*" ]
    p2=[ "1", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==[]
    assert d2==[]

def compareTr_equal3_test():
    p1=[ "1", "2", "3" ]
    p2=[ "*", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==[]
    assert d2==[]

def compareTr_equal4_test():
    p1=[ "*", "2", "*" ]
    p2=[ "*", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==[]
    assert d2==[]


def compareTr_tail_test():
    p1=[ "1", "2", "3", "4" ]
    p2=[ "1", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==["4"]
    assert d2==[]

def compareTr_tail1_test():
    p1=[ "1", "2", "3" ]
    p2=[ "1", "2", "3", "4" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==[]
    assert d2==["4"]


def compareTr_tail2_test():
    p1=[ "1", "2", "3" ]
    p2=[ "1", "2", "3", "4", "5" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==[]
    assert d2==["4", "5"]

def compareTr_tail3_test():
    p1=[ "1", "2", "3", "4", "5" ]
    p2=[ "1", "2", "3"  ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 3
    assert d1==["4", "5"]
    assert d2==[]

def compareTr_head1_test():
    p1=[           "3", "4", "5" ]
    p2=[ "1", "2", "3", "4", "5" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[]
    assert d2==["1", "2"]

def compareTr_head2_test():
    p1=[ "1", "2", "3", "4", "5" ]
    p2=[      "2", "3", "4", "5" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==["1"]
    assert d2==[]

def compareTr_diff1_test():
    p1=[ "11", "2", "3" ]
    p2=[ "1", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[ "11" ]
    assert d2==[ "1" ]

def compareTr_diff2_test():
    p1=[ "11", "2", "3" ]
    p2=[ "1", "2", "33" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[ "11", "2", "3" ]
    assert d2==[ "1", "2", "33" ]

def compareTr_diff3_test():
    p1=[ "11", "111", "2", "3" ]
    p2=[ "1", "2", "3" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[ "11", "111" ]
    assert d2==[ "1" ]

def compareTr_diff4_test():
    p1=[ "1", "2", "4" ]
    p2=[ "1", "2", "3", "4" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 2
    assert d1==[  ]
    assert d2==[ "3" ]

def compareTr_diff5_test():
    p1=[ "1", "2", "4" ]
    p2=[ "1", "2", "*", "4" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 2
    assert d1==[  ]
    assert d2==[ "*" ]

def compareTr_diff6_test():
    p1=[      "2", "3", "4" ]
    p2=[ "*", "2", "3", "4" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 0
    assert d1==[  ]
    assert d2==[ "*" ]

def compareTr_diff7_test():
    p1=[ "1", "2", "*", "*" ]
    p2=[ "*", "2", "3", "4", "*" ]
    d = comparePaths( p1, p2 )
    head, d1, d2 = d.pos, d.pathfrom, d.pathto
    assert head == 4
    assert d1==[  ]
    assert d2==[ "*" ]

#    import pdb; pdb.set_trace()



# ==== Events    

def getTrEvents(m, p, tmin=None, tmax=None, eqset=None):

    if eqset==None:
        eqset=EqSet()
        eqset.computeRepresentatives()

    if tmin==tmax==None:
        cursor=(tr.find( {"prb_id": p, "msm_id": m },
                        {"hops": 1, "startTimestamp":1, "_id":0})
                .sort("startTimestamp")
                )
    else:
        cursor=(tr.find( {"prb_id": p, "msm_id": m, "startTimestamp": {"$gte":tmin, "$lte": tmax } },
                        {"hops": 1, "startTimestamp":1, "_id":0})
                    .sort("startTimestamp")
                    )

    while True:
        prv = extract(cursor.next(), eqset)
        if prv.rtt != None:
            break

    for curr in cursor:
        crr = extract(curr, eqset)
        # Note: we don't skip incomplete traceroutes, unreachabilities are important
        d = comparePaths(prv.path, crr.path)
        if not prv.timestamp < crr.timestamp:
            continue
        tre = TrEvent(d, p, m, prv.timestamp, crr.timestamp, prv.rtt, crr.rtt)
        if tre.distance > 0:
            yield prv, tre, crr
        prv = crr


def count_traceroutes(source, target, start_timestamp, end_timestamp):
    query = {"prb_id": source, "msm_id": target,
             "startTimestamp": {"$gte": start_timestamp, "$lte": end_timestamp }}
    fields = {"_id": 1}
    num_traceroutes = tr.find(query, fields).count()
    return num_traceroutes


#---------
def print_events(m, p, tmin=None, tmax=None, eqset=None):
    print "tmin=", time.strftime(fmt, time.gmtime(tmin))
    print "tmax=", time.strftime(fmt, time.gmtime(tmax))
    print "eqset=", eqset
    c=0
    for frm, trevent, to in getTrEvents(m, p, tmin, tmax, eqset):
        c+=1
        print time.strftime(fmt, time.gmtime(trevent.from_timestamp))
        print " "*7, trevent.pathfrom
        print " "*7, trevent.pathto
        print time.strftime(fmt, time.gmtime(trevent.to_timestamp))
        print ""
        #print trevent.dictRepr()
    print "number of events: ", c


unpopiudimezzora=60*60/2*1.2
dieciminuti=60*10
unoraemezza=int(60*60*1.5)
unpomenodiunora=int(60*60*0.9)



                                                                                                                                                        
# ==== Analysis        

def compute_pre_and_post_sets(AS, tmin, tmax, eqset, deltat=dieciminuti):
    """AS is an AS number (integer) or -1 (meaning all ASes), tmin and tmax are two unix timestamps, eqset is the equivalence set
    representing load ballancer (EqSet instance), deltat is the maximum number of seconds after an event
    to look for related events.
    """

    if AS > 0:
        pairs = find_prb_dest_pairs_for_AS(AS)
    else:
        pairs = find_prb_dest_pairs_all()
    c = SortedCollection(key= (lambda ev: ev.from_timestamp) ) # collection of all TrEvents sorted by from_timestamp
    for dest, probe in pairs:
        for frm, trevent, to in getTrEvents(dest, probe, tmin, tmax, eqset):
            c.insert(trevent)

    pre=set()
    post=set()
    for event in c:
        t=event.from_timestamp

        # look for related events forward in time (just forward to avoid duplicate the related pairs)
        idx=c.index(event)+1  # start from the next event
        while idx <= len(c)-1 and c[idx].from_timestamp - t < deltat:
            event2=c[idx]

            #check for pre-relatedness
            if not set(event2.pathfrom).isdisjoint(set(event.pathfrom)):
                #print "pre"
                #print " "*5, event.msm_id, event.prb_id, time.strftime(fmt, time.gmtime(event.from_timestamp)), event.pathfrom
                #print " "*5, event2.msm_id, event2.prb_id, time.strftime(fmt, time.gmtime(event2.from_timestamp)), event2.pathfrom
                #print " "*5, set(event2.pathfrom).intersection(set(event.pathfrom))
                #print
                pre.add((event, event2))
            #check for post-relatedness
            if not set(event2.pathto).isdisjoint(set(event.pathto)):
                #print "post"
                #print " "*5, event.msm_id, event.prb_id, time.strftime(fmt, time.gmtime(event.from_timestamp)), event.pathto
                #print " "*5, event2.msm_id, event2.prb_id, time.strftime(fmt, time.gmtime(event2.from_timestamp)), event2.pathto
                #print " "*5, set(event2.pathto).intersection(set(event.pathto))
                #print
                post.add((event, event2))
            idx+=1
    return {
        "pre": pre,
        "post": post
    }
    #print "number of events: ", len(c)
    #print "number of pre-relations: ", len(pre)
    #print "number of post-relations: ", len(post)


def get_relevant_pair_data(pairs):
    relevant_data = []
    for pair in pairs:
        relevant_data.append({
            "event1": {
                "msm_id": pair[0].msm_id,
                "prb_id": pair[0].prb_id,
                "timestamp": pair[0].from_timestamp,
                "from_rtt": pair[0].from_rtt,
                "to_rtt": pair[0].to_rtt,
                "from_path": pair[0].pathfrom,
                "to_path": pair[0].pathto,
                "lengthfrom": pair[0].lengthfrom,
                "lengthto": pair[0].lengthto,
                "pos": pair[0].pos
            },
            "event2": {
                "msm_id": pair[1].msm_id,
                "prb_id": pair[1].prb_id,
                "timestamp": pair[1].from_timestamp,
                "from_rtt": pair[1].from_rtt,
                "to_rtt": pair[1].to_rtt,
                "from_path": pair[1].pathfrom,
                "to_path": pair[1].pathto,
                "lengthfrom": pair[1].lengthfrom,
                "lengthto": pair[1].lengthto,
                "pos": pair[1].pos
            }
        })
    return relevant_data


def json_format_pre_and_post_sets(AS, tmin, tmax, eqset, deltat=dieciminuti):
    pre_and_post = compute_pre_and_post_sets(AS, tmin, tmax, eqset, deltat)
    pre_info = get_relevant_pair_data(pre_and_post["pre"])
    post_info = get_relevant_pair_data(pre_and_post["post"])
    serializable_pre_post = {
        "tmin": tmin,
        "tmax": tmax,
        "pre": pre_info,
        "post": post_info
    }
    return serializable_pre_post


def print_json_pre_and_post(AS, tmin, tmax, eqset, deltat=dieciminuti):
    print json.dumps(json_format_pre_and_post_sets(AS, tmin, tmax, eqset, deltat), indent=4)


def tr_count_for_graph_analysis(AS, graph_analysis, deltat):
    """changes graph_analysis adding tr_count statistics"""
    pairs = find_prb_dest_pairs_for_AS(AS)
    tsseq = SortedCollection() # collection of all timestamps of traceroute
    for dest, probe in pairs:
        cursor=tr.find({'prb_id':probe, 'msm_id':dest}, {'startTimestamp':1})
        for curr in cursor:
            tsseq.insert(curr['startTimestamp'])
    for kind in ["pre", "post"]:
        for d in graph_analysis[kind]:
            ts1=tsseq.find_ge(d['start'])

            # count traceroutes with timestamp within [ts1, ts1+deltat]
            idx=tsseq.index(ts1)
            tr_count=1
            while tsseq[idx]<=ts1+deltat:
                tr_count+=1
                idx+=1
            d['analysis']['tr_count']=tr_count

import re

def analyze_pre_and_post(AS, tmin, tmax, eqset, deltat, step, thresholdOk):
    pre_and_post = json_format_pre_and_post_sets(AS, tmin, tmax, eqset, deltat)
    graph_analysis = correlation_graph_analysis.analyze_graph_with_sliding_window(pre_and_post, window=deltat, step=step)

    tr_count_for_graph_analysis(AS,graph_analysis,deltat) # add tr_count statistics

    for d in graph_analysis["pre"]:
        an = d["analysis"]
        print "%d\t"*13 %(d["start"], an["edge_count"], an["node_count"],
            an["max_connected_component_size"], an["max_clique_size"],an['tr_count'], an["most_common_msm_count_in_max_cc"],
            an["most_common_prb_count_in_max_cc"],an["most_common_msm_count_in_max_clique"], an["most_common_prb_count_in_max_clique"],
            an["min_deltartt"], an["max_deltartt"], an["avg_deltartt"]
            )
    print ""
    print ""
    for d in graph_analysis["post"]:
        an = d["analysis"]
        print "%d\t"*13 %(d["start"], an["edge_count"], an["node_count"],
            an["max_connected_component_size"], an["max_clique_size"],an['tr_count'],an["most_common_msm_count_in_max_cc"],
            an["most_common_prb_count_in_max_cc"],an["most_common_msm_count_in_max_clique"], an["most_common_prb_count_in_max_clique"],
            an["min_deltartt"], an["max_deltartt"], an["avg_deltartt"]
            )
    print ""
    print ""

    #########  --- now look for events (maximum of max_clique_size) ----

    maxima=[]  # list of unix timestamp, maxima of max clique values for pre-empathy and post-empathy graph series

    lastThreeVals={'pre':[], 'post':[]}
    cmqs={'pre':None, 'post':None}
    startts={'pre':None, 'post':None}
    d={'pre':None, 'post':None}
    lastmaximum={'pre':None, 'post':None}
    for d['pre'], d['post'] in zip(graph_analysis["pre"], graph_analysis['post']):
        for kind in 'pre','post':
            cmqs[kind] = d[kind]["analysis"]["max_clique_size"] # current maximum clique size
            startts[kind]=d[kind]["start"]
            if len(lastThreeVals[kind])==0:   # put the first
                lastThreeVals[kind].append((cmqs[kind], startts[kind]))  # startts is the timestamp (unix) where the value has been seen the first time
            else:
                if cmqs[kind] != lastThreeVals[kind][-1][0]:   # update
                    lastThreeVals[kind].append((cmqs[kind],startts[kind]))
                if len(lastThreeVals[kind])>3:  # too long? delete the last in the queue (first in the list)
                    del lastThreeVals[kind][0]

            assert len(lastThreeVals[kind])<=3

            if len(lastThreeVals[kind])<3:
                continue

            if lastThreeVals[kind][0][0]< lastThreeVals[kind][1][0] and lastThreeVals[kind][2][0]< lastThreeVals[kind][1][0] and lastThreeVals[kind][1][0]>=thresholdOk: # check for a maximum to be reported
                startunix=lastThreeVals[kind][1][1]
                if lastmaximum[kind]!=startunix:
                    maxima.append((startunix,kind))
                    lastmaximum[kind]=startunix


    log('found %s maxima, starting reporting' % len(maxima))
    i=0
    if args.regexp:
        cregexp=re.compile(args.regexp)
    else:
        cregexp=None
    with file(args.outreport, "w") as report:
        report.write("AS=%d starttime=%s endtime=%s threshold=%d\n" % (AS, time.strftime(fmt, time.gmtime(tmin)), time.strftime(fmt, time.gmtime(tmax)), thresholdOk))
        for maximum, kind in maxima:
            startreadable=time.strftime(fmt, time.gmtime(maximum))
            kindforuser= kind.upper()
            events={}
            events['pre'], events['post']= get_events_at_time_from_json(pre_and_post,AS, tmin, tmax, eqset, maximum, deltat)
            g=graph_from_event_pairs(events[kind])

            cliques=list(networkx.find_cliques(g))
            cliques.sort(key=len)
            cliques.reverse()

            record = "%s -----------------------  %s (%d) \n" % (kindforuser, startreadable, maximum)
            ind=" "*4
            record += ind*1+"cliques (size):"
            for clq in cliques:
                if len(clq)<thresholdOk:
                    break
                record += " %d" % len(clq)
            record += '\n'

            for clq in cliques:

                if len(clq)<thresholdOk:
                    break

                def probes(msm, clq):
                    """returns the probes for a certain destination in a clique"""
                    L=[ src for dest, src in clq if dest == msm  ]
                    return list(set(L))

                def targets(prb, clq):
                    """returns the targets for a certain probe in a clique"""
                    L=[ dest for dest, src in clq if src == prb  ]
                    return list(set(L))

                msm_list_in_clique = map(lambda x: x[0], clq)
                msm_list_with_count = map( lambda x: (x, msm_list_in_clique.count(x)), set(msm_list_in_clique) )
                msm_list_with_count.sort(key=lambda x: x[1])
                msm_list_with_count.reverse()

                prb_list_in_clique = map(lambda x: x[1], clq)
                prb_list_with_count = map( lambda x: (x, prb_list_in_clique.count(x)), set(prb_list_in_clique) )
                prb_list_with_count.sort(key=lambda x: x[1])
                prb_list_with_count.reverse()

                from collections import defaultdict
                nodestats=defaultdict(int)
                for v in clq:
                    #print '   ', v
                    #pprint(g.node[v]['events'], indent=4)
                    path=next(iter(g.node[v]['events']))[ 'to_path' if kind=='post' else 'from_path']
                    for ip in set(path):
                        nodestats[ip]+=1

                recordClq = ind*1+"size = %d\n" % len(clq)

                for prb, _ in prb_list_with_count:
                    T=targets(prb,clq)
                    recordClq += ind*2+"probe  %d -> %d targets: %r\n" % ( prb, len(T), T )

                for msm, _ in msm_list_with_count:
                    P=probes(msm,clq)
                    recordClq += ind*2+"target %d <- %d probes: %r\n" % ( msm, len(P), P )



                listnodestats=nodestats.items()
                listnodestats.sort(key=lambda x: x[1])
                listnodestats.reverse()

                topIpReport=""
                for ip, count in listnodestats:
                    if count<len(clq)/2:
                        break

                    topIpReport += ind*3+"%d: %s"% (count, ip)

                    if args.net:
                        import socket
                        netnameAndMaintainer=whoisInetnum(ip)
                        topIpReport += ' '+netnameAndMaintainer
                        socket.setdefaulttimeout(0.3)
                        try:
                            name=socket.gethostbyaddr(ip)[0]
                            topIpReport += ' '+name
                        except: pass

                    asNum, asName = Ip2ASresolver.instance.getASInfo(ip)
                    if asNum:
                        topIpReport += " AS%s %s" % (asNum, asName)

                    topIpReport += "\n"

                if cregexp and len(cregexp.findall(topIpReport))==0:
                    log('s', sameline=True)
                    continue #skip non matching recoreds

                recordClq += ind*2+"top frequent ip's:\n"
                recordClq += topIpReport

                msm_list_with_count.sort()

                for msm, _ in msm_list_with_count:
                    q = "http://amarone.dia.uniroma3.it/tplay/client/leone/run_tplay.html?"
                    q +="resource=" + str(msm)
                    q +="&starttime=" + str((maximum - 3600))
                    q +="&endtime=" + str((maximum + 2*3600))
                    q +="&selectedProbes=" + reduce( lambda x,y: x + "," + y, map(str, probes(msm, clq)) )
                    recordClq += ind*2+"%d %r\n" % (msm, q)

                def appendASInfoToIp(ip):
                    "returns ip with ASinfo appended"
                    rep=False
                    if ip[-1]=='*':
                        rep=True
                        ip=ip[:-1]
                    ASnum = Ip2ASresolver.instance.getASInfo(ip)[0]
                    if ASnum:
                        return ip+('*' if rep else '_')+ASnum
                    else:
                        return ip

                clq.sort()
                for v in clq:
                    event = next(iter(g.node[v]['events']))
                    from_path= map(appendASInfoToIp,event[ 'from_path' ])
                    to_path=   map(appendASInfoToIp,event[ 'to_path' ])
                    recordClq += ind*2+'- %d ->  %d  (pos=%d, lenfrom=%d, lento=%d)\n' % (v[1], v[0], event['pos'], event['lengthfrom'], event['lengthto'])
                    for p in from_path, to_path:
                        if len(p)==0:
                            recordClq += ind*3+'empty\n'
                        elif len(p)==1:
                            recordClq += ind*3+p[0]+'\n'
                        else:
                            recordClq += ind*3+reduce( lambda x,y: x+' '+y ,p) +'\n'
                recordClq += '\n'

                record += recordClq
            report.write(record)
            report.flush()
            i+=1
            if i%10==0:
                log(str(i), sameline=True)
            else:
                log('.', sameline=True)
        log('')  # new line
        log('Reporting finished.')  # new line




def whoisInetnum(ip):
    """ ip is a string representing an ip address. Returns a string describing the "owner" of the ip. It uses the whois command of the unix system."""
    import subprocess
    global args
    assert args.net
    if ip == "*":
        return ""
    if ip[-1]=="*" and len(ip)>1:
        ip=ip[:-1]
    command= " whois " + ip +  """ | awk -v RS='' -v FS='\n' '$1~/inetnum/ {print}' | egrep 'netname|mnt-by' | awk '{printf "%s ", $2}' """
    process=subprocess.Popen( command, shell=True, stdout=subprocess.PIPE)
    v=process.stdout.readline()
    process.wait()
    return v.strip(' \n')


class hashabledict(dict):
    def __hash__(self):
        items=[ (k,v) for k, v in self.iteritems() if k not in ['from_path', 'to_path'] ]
        return hash(frozenset(items))

def graph_from_event_pairs(pairs):
    graph = networkx.Graph()

    for pair in pairs:
        v1=(pair["event1"]["msm_id"], pair["event1"]["prb_id"])
        v2=(pair["event2"]["msm_id"], pair["event2"]["prb_id"])
        graph.add_edge(v1, v2)

        for v, ev in [ (v1,pair["event1"]), (v2, pair["event2"]) ]:
            if not graph.node[v].has_key('events'):
                graph.node[v]['events']=set()
                graph.node[v]['n']=0

            hd=hashabledict(ev)
            #print v, hash(hd), hd
            graph.node[v]['events'].add(hd)
            graph.node[v]['n']+=1

    return graph


def get_events_at_time_from_json(info, AS, tmin, tmax, eqset, starttime, window):
    """ info: is a json-derived structure """
    start = starttime
    end = start + window

    pre = [i for i in info["pre"]
             if start <= i["event1"]["timestamp"] < end  and start <= i["event2"]["timestamp"] < end]
    post = [i for i in info["post"]
             if start <= i["event1"]["timestamp"] < end  and start <= i["event2"]["timestamp"] < end]
    return (pre, post)


def get_events_at_time(AS, tmin, tmax, eqset, starttime, window):
    info = json_format_pre_and_post_sets(AS, tmin, tmax, eqset, deltat=window)
    return get_events_at_time_from_json(info, AS, tmin, tmax, eqset, starttime, window)

def print_all_relations_for_an_as(AS, tmin, tmax, eqset, deltat=dieciminuti):
    """AS is an AS number (integer), tmin and tmax are two unix timestamps, eqset is the equivalence set
    representing load ballancer (EqSet instance), deltat is the number of seconds before or after an event
    to look for related events.
    """
    c = SortedCollection(key= (lambda ev: ev.from_timestamp) ) # collection of all TrEvents sorted by from_timestamp
    pairs = find_prb_dest_pairs_for_AS(AS)
    for dest, probe in pairs:
        for frm, trevent, to in getTrEvents(dest, probe, tmin, tmax, eqset):
            c.insert(trevent)

    pre=set()
    post=set()
    for event in c:
        t=event.from_timestamp

        # look for related events forward in time (just forward to avoid duplicate the related pairs)
        idx=c.index(event)+1  # start from the next event
        while idx <= len(c)-1 and c[idx].from_timestamp - t < deltat:
            event2=c[idx]

            #check for pre-relatedness
            if not set(event2.pathfrom).isdisjoint(set(event.pathfrom)):
                print "pre"
                print " "*5, event.msm_id, event.prb_id, time.strftime(fmt, time.gmtime(event.from_timestamp)), event.pathfrom
                print " "*5, event2.msm_id, event2.prb_id, time.strftime(fmt, time.gmtime(event2.from_timestamp)), event2.pathfrom
                print " "*5, set(event2.pathfrom).intersection(set(event.pathfrom))
                print
                pre.add((event, event2))
            #check for post-relatedness
            if not set(event2.pathto).isdisjoint(set(event.pathto)):
                print "post"
                print " "*5, event.msm_id, event.prb_id, time.strftime(fmt, time.gmtime(event.from_timestamp)), event.pathto
                print " "*5, event2.msm_id, event2.prb_id, time.strftime(fmt, time.gmtime(event2.from_timestamp)), event2.pathto
                print " "*5, set(event2.pathto).intersection(set(event.pathto))
                print
                post.add((event, event2))
            idx+=1
    print "number of events: ", len(c)
    print "number of pre-relations: ", len(pre)
    print "number of post-relations: ", len(post)


def report_lb_trevents_for_as(AS, tmin, tmax, eqset):
    pairs = find_prb_dest_pairs_for_AS(AS)
    for dest, probe in pairs:
        print "------------- dest=",dest, " probe=",probe
        for frm, trevent, to in getTrEvents(dest, probe, tmin, tmax, eqset):
            if not set(trevent.pathfrom).isdisjoint(set(trevent.pathto)):
                print time.strftime(fmt, time.gmtime(trevent.from_timestamp)), trevent.pos
                print " "*5, trevent.pathfrom
                print " "*5, trevent.pathto



def contract(G, nodeset):
    # changes G by substituting nodeset with a single node_count

    G1=G.subgraph(nodeset)


    neighbour=set()
    for n in nodeset:
        for n_near in G[n]:
            if n_near not in nodeset:
                neighbour.add(n_near)
    G.remove_nodes_from(nodeset)
    center="c(%d,%d)" % (len(nodeset), G1.number_of_edges())
    if len(neighbour)==0:
        G.add_node( center )
    else:
        G.add_star( [ center ] + list(neighbour)  )

class Ip2ASresolver:
    def __init__(self):
        self._map={}
        for x in db.ip2as.find( {}, {"_id":0, "address":1, "as_numbers":1}):
            assert len(x['as_numbers'])<=1
            if len(x['as_numbers'])==0:
                continue
            as_name = x['as_numbers'][0]['holder']
            as_number = x['as_numbers'][0]['asn']
            ip= x['address']
            assert not self._map.has_key(ip)
            self._map[ip]= (as_number, as_name)

    def getASInfo(self, ip):
        if len(ip)>1 and ip[-1]=="*": #strip '*' off if any
            ip=ip[:-1]


        try:
            as_number, as_name = self._map[ip]
        except:
            as_number, as_name  = (None,None)
        return ( as_number, as_name )














# ==== load balancing heuristic      

def routingAnalysisLB(AS, tmin, tmax):
    """perform statistical analysis of routing evolution for probes in one AS toward all destinations. 
    Retruns a graph with proper labeling.
    """
    class VStatus:
        def __init__(self):
            self.routing=None # string, an ip address
            self.since=None # unix time
        def set(self,addr, time):
            self.routing=addr
            self.since=time
        def __str__(self):
            return "addr=%s since=%d" % (self.routing if self.routing else "",
                                         self.since if self.since else -1)
        def __repr__(self):
            return str(self)

    class EStat:
        def __init__(self):
            self.sdpair=set() # the sdpair's that uses this link in their routing history
            self.number_routing_on=0 # integer, the number of times the routing switched on this edge
            self.number_routing_off=0 # integer, the number of times the routing switched away from this edge
            self.number_routing_confirm=0 # integer, the number of times a traceroute confirmed the routing on this edge (all times after the first)
            self.routing_burst_sum=0  # the total amount of time the routing was on this edge
            self.min_routing_burst_duration=999999999999
            self.max_routing_burst_duration=0

        def routing_on(self, sdpair):
            self.number_routing_on+=1
            self.sdpair.add(sdpair)

        def routing_confirm(self):
            self.number_routing_confirm+=1

        def routing_off(self, on_time, off_time):
            self.number_routing_off+=1
            duration=off_time-on_time
            assert duration>=0
            self.routing_burst_sum+=duration
            self.min_routing_burst_duration=min(self.min_routing_burst_duration,duration)
            self.max_routing_burst_duration=max(self.max_routing_burst_duration,duration)

        def __str__(self):
            return "sdpairs=%d on=%d conf=%d off=%d avg=%d min=%d max=%d" % (
                len(self.sdpair),
                self.number_routing_on,
                self.number_routing_confirm,
                self.number_routing_off,
                self.routing_burst_sum/(self.number_routing_on),
                self.min_routing_burst_duration,
                self.max_routing_burst_duration)
        def __repr__(self):
            return str(self)

    g=networkx.DiGraph()

    if AS > 0:
        pairs = find_prb_dest_pairs_for_AS(AS)
        for dest, probe in pairs:
            # reset routing status in the graph
            for n in g:
                g.node[n]['status'].routing=None
                g.node[n]['status'].since=None

            # query routing history for the source dest pair.
            cursor=(tr.find( {"msm_id": dest,
                              'prb_id': probe,
                              "startTimestamp": {"$gte":tmin, "$lte": tmax } },
                            {"hops": 1, "prb_id":1, "startTimestamp":1, "_id":0})
                    .sort("startTimestamp")
                    )

            for curr in cursor:
                # consider the path
                crr= extract(curr,eqset=None)
                path=crr.path
                time=crr.timestamp

                #skip short traceroutes
                if len(path)<2:
                    continue

                prevaddr = path[0]
                for curraddr in path[1:]: #starting from the second hop

                    # skip hops with incomplete information
                    if prevaddr=='*' or curraddr=='*':
                        prevaddr=curraddr
                        continue

                    # ensure nodes and edges are there
                    if not g.has_node(prevaddr): g.add_node(prevaddr,status=VStatus())
                    if not g.has_node(curraddr): g.add_node(curraddr,status=VStatus())
                    if not g.has_edge(prevaddr,curraddr): g.add_edge(prevaddr,curraddr, stats=EStat())

                    r=g.node[prevaddr]['status'].routing
                    since=g.node[prevaddr]['status'].since
                    if r:
                        assert since

                        if r == curraddr:
                            g.edge[prevaddr][curraddr]['stats'].routing_confirm()
                        else:
                            g.edge[prevaddr][r]['stats'].routing_off(on_time=since, off_time=time)

                            g.node[prevaddr]['status'].set(curraddr,time)
                            g.edge[prevaddr][curraddr]['stats'].routing_on((probe,dest))
                    else:
                        g.node[prevaddr]['status'].set(curraddr,time)
                        g.edge[prevaddr][curraddr]['stats'].routing_on((probe,dest))

                    assert g.node[prevaddr]['status'].routing
                    assert g.node[prevaddr]['status'].since

                    prevaddr=curraddr
    else:

        # TODO: this branch of the if is a modified version of the other branch.
        # Find the common parts and refactor!

        # query routing history for the source dest pair.
        cursor=(tr.find( {"startTimestamp": {"$gte":tmin, "$lte": tmax } },
                        {"hops": 1, "prb_id":1, "msm_id": 1, "startTimestamp":1, "_id":0})
                .sort("startTimestamp")
                )
        n=0
        for curr in cursor:
            if n % 50000 == 0: 
                log(str(n))
            n+=1
            probe=curr["prb_id"]
            dest=curr["msm_id"]
            # consider the path
            crr= extract(curr,eqset=None)
            path=crr.path
            time=crr.timestamp

            #skip short traceroutes
            if len(path)<2:
                continue

            prevaddr = path[0]
            for curraddr in path[1:]: #starting from the second hop

                # skip hops with incomplete information
                if prevaddr=='*' or curraddr=='*':
                    prevaddr=curraddr
                    continue

                # ensure nodes and edges are there
                if not g.has_node(prevaddr): g.add_node(prevaddr,status=VStatus())
                if not g.has_node(curraddr): g.add_node(curraddr,status=VStatus())
                if not g.has_edge(prevaddr,curraddr): g.add_edge(prevaddr,curraddr, stats=EStat())

                r=g.node[prevaddr]['status'].routing
                since=g.node[prevaddr]['status'].since
                if r:
                    assert since

                    if r == curraddr:
                        g.edge[prevaddr][curraddr]['stats'].routing_confirm()
                    else:
                        g.edge[prevaddr][r]['stats'].routing_off(on_time=since, off_time=time)

                        g.node[prevaddr]['status'].set(curraddr,time)
                        g.edge[prevaddr][curraddr]['stats'].routing_on((probe,dest))
                else:
                    g.node[prevaddr]['status'].set(curraddr,time)
                    g.edge[prevaddr][curraddr]['stats'].routing_on((probe,dest))

                assert g.node[prevaddr]['status'].routing
                assert g.node[prevaddr]['status'].since

                prevaddr=curraddr
    return g


def stabilityIndex( edgestats ):
    conf = edgestats.number_routing_confirm
    on = edgestats.number_routing_on
    off = edgestats.number_routing_off
    number_of_samples=conf+on+off
    return float(conf)/number_of_samples


def inferLB(g):
    """ from a labelled graph computed by routingAnalysis() it infers possible Load Balancers and return an EqSet instance"""


    LBcandidates=[]

    for v in g.nodes():
        lb=set()   # WARNING infers at most one lb for each node
        neighborStatList= map( lambda x: (x[1],x[2]), g.out_edges([v], data=True) )   # strip off first element of the tuple (always equal to v)
        neighborIndexList= map( lambda x: (x[0], stabilityIndex(x[1]['stats']) ), neighborStatList)
        neighborIndexList.sort(key=lambda x: x[1])
        for neighbour, index in neighborIndexList:
            if index < 0.8:
                lb.add(neighbour)
        if len(lb)>1:
            as_2_lb = {}
            for ip in lb:
                as_info = Ip2ASresolver.instance.getASInfo(ip)
                if not as_info[0] in as_2_lb:
                    as_2_lb[as_info[0]] = []
                as_2_lb[as_info[0]].append(ip)
            for as_num in as_2_lb:
                lb = as_2_lb[as_num]
                lb=list(lb)
                lb.sort()
                if len(lb) > 1:
                    LBcandidates.append(tuple(lb))

    from collections import defaultdict
    ipstats=defaultdict(int)
    for lbcand in LBcandidates:
        for ip in lbcand:
            ipstats[ip]+=1
    lbscore=defaultdict(int)
    for lbcand in LBcandidates:
        assert len(lbcand)>1
        lbscore[lbcand]= reduce( lambda x,y: ipstats[x]+ipstats[y], lbcand )  # correct since len(lbcand)>1
    LBcandidates.sort(key=lambda lbcand: lbscore[lbcand] )
    LBcandidates.reverse()

    eqset=EqSet()
    for c in LBcandidates:
        eqset.add(c)
    return eqset

def reportLB(g,filestream):
    """ write the stats in g into filestream """
    f=filestream
    ind=' '*4
    for v in g.nodes():
        f.write( str(v)+'\n')
        neighborStatList= map( lambda x: (x[1],stabilityIndex(x[2]['stats']), x[2]), g.out_edges([v], data=True) )   # strip off first element of the tuple (always equal to v)
        for neighbor, index, stat in neighborStatList:
            f.write(ind*1+"%s %f %s\n" %(neighbor, index, str(stat)) )


def op_analysis():
    log("AS=%d starttime=%s endtime=%s threshold=%d" % (AS, starttime, endtime, args.threshold))

    if args.load:
        log("Loading load balancers from file: %s" % args.load )
        eqset= EqSet.load(file(args.load))
    else:
        log("*** no load balancer data specified (use --load)***" )
        eqset = EqSet()
        eqset.computeRepresentatives()


    log("analysing.")
    analyze_pre_and_post(AS, tmin, tmax, eqset,
                          deltat=unpomenodiunora,
                          step=60,
                          thresholdOk=args.threshold)


def op_great_analysis():

    global AS

    if args.load:
        log("Loading load balancers from file: %s" % args.load )
        eqset= EqSet.load(file(args.load))
    else:
        log("*** running with no load balancer knowledge  (use --lbsets and then --load)***" )
        eqset = EqSet()
        eqset.computeRepresentatives()

    if AS > 0:
        pairs = find_prb_dest_pairs_for_AS(AS)
    else:
        pairs = find_prb_dest_pairs_all()
    log("### number of sdpairs: %d" %len(pairs))

    log("computing transitions")
    # index transitions by start and end
    timestamps = SortedSet()
    t2transitionStart = {}
    t2transitionEnd = {}
    num_traceroutes = 0
    num_transitions = 0
    # sd-pairs for which some traceroute is found in the given time interval
    nonempty_sdpairs = []


    time_start_of_phase1 = datetime.now()
    for destination, probe in pairs:
        num_traceroutes_sd = count_traceroutes(probe, destination, tmin, tmax)
        num_traceroutes += num_traceroutes_sd
        if num_traceroutes_sd > 0:
            nonempty_sdpairs.append((probe, destination))
        for frm, transition, to in getTrEvents(destination, probe, tmin, tmax, eqset):
            num_transitions += 1
            sd_pair = (probe, destination)
            ips = [(ip, "pre") for ip in transition.pathfrom] + [(ip, "post") for ip in transition.pathto]
            timestamps.add(transition.from_timestamp)
            timestamps.add(transition.to_timestamp)
            our_transition = (sd_pair,
                              tuple(ips),
                              tuple(transition.pathfrom),
                              tuple(transition.pathto),
                              transition.from_timestamp,
                              transition.to_timestamp,
                              transition.lengthfrom,
                              transition.lengthto,
                              transition.distance,
                              frm, transition, to)
            if not transition.from_timestamp in t2transitionStart:
                t2transitionStart[transition.from_timestamp] = set()
            if not transition.to_timestamp in t2transitionEnd:
                t2transitionEnd[transition.to_timestamp] = set()
            t2transitionStart[transition.from_timestamp].add(our_transition)
            t2transitionEnd[transition.to_timestamp].add(our_transition)


    time_start_of_phase2 = datetime.now()

    log("phase 1 (transitions) took %d seconds for %d traceroutes and %d transitions." % ( (time_start_of_phase2-time_start_of_phase1).total_seconds(), num_traceroutes, num_transitions) )
    log("computing candidate events, one for each extended ip ")
    typedIp2queue = {}  # mapping from extended ip to queue of length 2 of <timestamp, set of sd-pairs>, the set of sd-pairs is represented as a tuple
    t2cliqueStart = {}  # clique = candidate event
    t2cliqueEnd = {}
    num_cliques=0
    log("    numumber of timestamps to iter on: %d" % len(timestamps))
    counter = 0
    for t in timestamps:
        if counter % (int(len(timestamps) * 0.01)) == 0:
            log("      timestamp: %d / %d" % (counter, len(timestamps)))
        counter += 1
        if t in t2transitionEnd:  # in t there is some transitions that end
            for transition in t2transitionEnd[t]:  # let's iter over those that end
                for ip in transition[1]:  #let's iter over its extended ip's
                    current_state = (t, typedIp2queue[ip][1][1] - {transition[0]}) # remove the sd-pair (since this transition ends)
                    if len(typedIp2queue[ip][1][1]) > len(typedIp2queue[ip][0][1]):
                        # clique is: (start, end, ip, sdpairs)
                        clique = CandidateEvent(start=typedIp2queue[ip][1][0],
                                                end=t,
                                                ip=ip,
                                                sdpairs=tuple(sorted(typedIp2queue[ip][1][1]))
                                                )
                        if not clique.start in t2cliqueStart:
                            t2cliqueStart[clique.start] = set()
                        if not clique.end in t2cliqueEnd:
                            t2cliqueEnd[clique.end] = set()
                        t2cliqueStart[clique.start].add(clique)
                        t2cliqueEnd[clique.end].add(clique)
                        num_cliques+=1
                        # comment R2.10a: gather size of S_A, that is len(sd_pairs) and make densit

                    #update queue
                    typedIp2queue[ip].pop(0)
                    typedIp2queue[ip].append(current_state)

        if t in t2transitionStart:
            for transition in t2transitionStart[t]:
                for ip in transition[1]:
                    #initialize queue
                    if not ip in typedIp2queue:
                        typedIp2queue[ip] = [(0, set()), (0, set())]  # queue of length 2, [first, last]

                    # add the sd-pair of the transition to the set of sd-pairs of the extended ip.
                    current_state = (t, typedIp2queue[ip][1][1] | {transition[0]})

                    #update queue
                    typedIp2queue[ip].pop(0)  # remove the first
                    typedIp2queue[ip].append(current_state) # enqueue a new one
    # log("t2cliqueEnd: ")
    # log(str(json.dumps(t2cliqueEnd, indent=4)))
    # log("")
    # log("t2cliqueStart: ")
    # log(str(json.dumps(t2cliqueStart, indent=4)))

    time_start_of_phase3 = datetime.now()
    log("phase 2 (computing candidate events (cliques)) took %d seconds for %d cliques." % ((time_start_of_phase3-time_start_of_phase2).total_seconds(), num_cliques) )

    if args.candidate_events_report != None:
        lastCE={}  # mapping from extended ip to last candidate event for it.
        with open(args.candidate_events_report, "w") as f:
            f.write("start\tend\tip\tscopesize\tseparation_from_last_for_same_eIP\tAS_of_IP\n")
            for t in timestamps:
                if t in t2cliqueEnd:
                    for c in t2cliqueEnd[t]:
                        lastCE[c.ip] = c
                if t in t2cliqueStart:
                    for c in t2cliqueStart[t]:
                        if c.ip in lastCE:
                            prevCE = lastCE[c.ip]
                            prevCE_sep = c.start - prevCE.end
                        else:
                            prevCE=None
                            prevCE_sep = "-"

                        lastCE[c.ip]=c

                        asinfo = Ip2ASresolver.instance.getASInfo(c.ip[0])
                        f.write("%d\t%d\t%s\t%d\t%s\t%s\n" % (c.start, c.end, c.ip, len(c.sdpairs), str(prevCE_sep), str(asinfo
                                                                                                                         )))


    log("starting phase 3: creating inferred events")
    #creating inferred events
    inferred_events = []
    active = set()
    inferred_event_id = 0
    counter = 0
    for t in timestamps:
        if counter % (int(len(timestamps) * 0.01)) == 0:
            log("      timestamp: %d / %d" % (counter, len(timestamps)))
        counter += 1
        if t in t2cliqueEnd:

            # skip (remove from active) all candidate events in active whose sdparis is a *proper* subset of other active ones
            for ending in t2cliqueEnd[t]:
                cliques_to_remove = set()
                for c in active:
                    if len(c.sdpairs) < len(ending.sdpairs) and\
                            set(c.sdpairs).issubset(set(ending.sdpairs)):   # proper subset check
                        cliques_to_remove.add(c)
                active = active.difference(cliques_to_remove)  #ignore them

            #for all ending candidate events, gather sdpair sets and map them to set of pairs
            # (extended ip sets, start time)
            sd_pair_set2ip_set = {}
            for ending in t2cliqueEnd[t].intersection(active):
                if not ending.sdpairs in sd_pair_set2ip_set:
                    sd_pair_set2ip_set[ending.sdpairs] = []
                sd_pair_set2ip_set[ending.sdpairs].append((ending.ip,ending.start))
                active.remove(ending)

            for sd_pair_set in sd_pair_set2ip_set:
                max_timestamp = max(sd_pair_set2ip_set[sd_pair_set], key=lambda x: x[1])[1]
                ips = map(lambda x: x[0], sd_pair_set2ip_set[sd_pair_set])
                if len(list(sd_pair_set)) >= args.threshold:
                    inferred_events.append(
                        {
                        "id": inferred_event_id,
                        "start": max_timestamp,
                        "end": t,
                        "sd_pairs": [{"probe": s, "target": d} for (s,d) in sd_pair_set],
                        "ips": list(ips)
                        }
                    )
                    inferred_event_id += 1

        if t in t2cliqueStart:
            active.update(t2cliqueStart[t])

    time_end_of_phase3 = datetime.now()
    log("phase 3 (create inferred events) took %d seconds for %d inferred events." % ((time_end_of_phase3-time_start_of_phase3).total_seconds(), len(inferred_events)) )



    inferred_events = filter(lambda x: not args.nowildcards or any((i[0] != "*") for i in x["ips"]),
                             inferred_events)

    command_line = reduce(lambda x, y: x + ' ' + y, sys.argv)

    # TrEvent:
    #     self.fullpathfrom=pd.fullpathfrom
    #     self.fullpathto=pd.fullpathto
    #     self.pathfrom=pd.pathfrom
    #     self.pathto=pd.pathto
    #     self.pos=pd.pos
    #     self.lengthfrom=pd.lengthfrom
    #     self.lengthto=pd.lengthto
    #     self.distance=pd.distance
    #     self.msm_id=mid
    #     self.prb_id=pid
    #     self.from_timestamp=fts
    #     self.to_timestamp=tts
    #     self.from_rtt= frtt
    #     self.to_rtt= trtt

    # claudio_transition:
    #     sd_pair
    #     tuple(ips)
    #     tuple(transition.pathfrom)
    #     tuple(transition.pathto)
    #     transition.from_timestamp
    #     transition.to_timestamp
    #     transition.lengthfrom
    #     transition.lengthto
    #     transition.distance

    if args.path_details:
        print "computing per-sdpair path details..."

        # Index transitions by sd-pair. This speeds-up the computation a lot
        sdpair2transitions = {}
        for claudio_transition in (tran for trans in t2transitionStart.itervalues() for tran in trans):
            sd_pair = claudio_transition[0]
            if sd_pair not in sdpair2transitions:
                sdpair2transitions[sd_pair] = []
            sdpair2transitions[sd_pair].append(claudio_transition)

        # Compare each event with all transitions of its sd-pairs,
        # keep the transitions that have an overlap in time with the event
        for event in inferred_events:
            for sd_pair_obj in event["sd_pairs"]:
                sd_pair = (sd_pair_obj["probe"], sd_pair_obj["target"])
                claudio_transitions = sdpair2transitions[sd_pair]
                for claudio_transition in claudio_transitions:
                    path_before = claudio_transition[9]
                    transition = claudio_transition[10]
                    path_after = claudio_transition[11]
                    if transition.from_timestamp <= event["start"] and transition.to_timestamp >= event["end"]:
                        sd_pair_obj["details"] = {
                            "path_before": path_before.path,
                            "path_after": path_after.path,
                            #"deltapre": transition.pathfrom,
                            #"deltapost": transition.pathto,
                            "deltapre_length": len(transition.pathfrom),
                            "deltapost_length": len(transition.pathto),
                            "position_of_delta": transition.pos
                        }

    if args.json:
        print "writing JSON output..."
        # Compute sd-pairs subject to some inferred event
        involved_sdpairs = set([(obj["probe"], obj["target"]) for event in inferred_events for obj in event["sd_pairs"]])
        json_report = {
            "events": inferred_events,
            "_num_traceroutes": num_traceroutes,
            "_num_transitions": num_transitions,
            "_num_events": len(inferred_events),
            "_interval_length": (tmax - tmin),
            "_num_involved_sdpairs": len(involved_sdpairs),
            "_num_nonempty_sdpairs": len(nonempty_sdpairs),
            "_command_line": repr(command_line)
        }
        with open("output.json", "w") as output_file:
            json.dump(json_report,output_file,indent=4)




def op_deltapreanalysis():



    assert args.AS==0, "cannot filter by AS, not implmented"


    if args.load:
        log("Loading load balancers from file: %s" % args.load )
        eqset= EqSet.load(file(args.load))
    else:
        log("*** running with no load balancer knowledge  (use --lbsets and then --load)***" )
        eqset = EqSet()
        eqset.computeRepresentatives()

    # pairs = find_prb_dest_pairs_all()
    # log("### number of sdpairs: %d" %len(pairs))

    ## all traceroutes in db
    if tmin==tmax==None:
        cursor=(tr.find( {},
                         {"hops": 1, "startTimestamp":1, "prb_id":1, "msm_id":1, "_id":0})
                .sort("startTimestamp")
                )
    else:
        cursor=(tr.find( {"startTimestamp": {"$gte":tmin, "$lte": tmax } },
                         {"hops": 1, "startTimestamp":1, "prb_id":1, "msm_id":1, "_id":0})
                .sort("startTimestamp")
                )

    cursor.noCursorTimeout()


    class DeltapreStat():
        __slots__ = ['ts','count', 'expired']
        def __init__(self, ts):
            self.ts = ts
            self.count = 0
            self.expired = False

        def inc(self):
            assert not self.expired
            self.count += 1

        def expire(self):
            self.expired = True



    # track the addresses appearing in delta pre
    tr_status = {}  # mapping da coppie (prb_id,msm_id) un traceroute come ritornato da extract()
    deltapre_status = {} # mapping from address to a list of DeltapreStat(timestamps, counter)
                    # each element is related to an occurrence of the address in a deltapre
                    # counter is the number of times addr was observed
                    # in a traceroute before T seconds from timestamps

    T = args.T

    log("reading and processing data with T="+str(T)+"..." )

    strtimeprev=""
    for curr in cursor:
        # if "prb_id" not in curr or "msm_id" not in curr: #skip malformed
        #     continue
        p=curr["prb_id"]
        m=curr["msm_id"]
        sdpair=(p,m)

        crr = extract(curr, eqset)

        strtimenow = time.strftime( "%Y-%m-%d %H", time.gmtime(crr.timestamp))
        if strtimenow != strtimeprev:
            strtimeprev = strtimenow
            log(strtimenow, True)
            count_active = 0
            count_inactive = 0
            for addr in deltapre_status:
                dpslist = deltapre_status[addr]
                for dps in dpslist:
                    if dps.count == 0:
                        count_inactive += 1
                    else:
                        count_active += 1
            log(" active: %d, inactive %d" %(count_active, count_inactive ))



        prv = tr_status.get(sdpair, None) # the first returns None, others a traceroute
        if prv == None:
            tr_status[sdpair] = crr
            continue

        if not prv.timestamp < crr.timestamp: # skip inverted
            continue


        for addr in crr.path:
            if addr in deltapre_status:
                tslist = deltapre_status[addr]
                for idx in xrange(len(tslist)):
                    dps = tslist[idx]
                    if crr.timestamp - dps.ts > T: # expired
                        dps.expire()
                    else:
                        dps.inc()


        d = comparePaths(prv.path, crr.path)
        tre = TrEvent(d, p, m, prv.timestamp, crr.timestamp, prv.rtt, crr.rtt) # this is a transition
        if tre.distance > 0:
            for addr in tre.pathfrom:
                if addr == "*":  # skip missing addresses
                    continue

                if addr not in deltapre_status:
                    deltapre_status[addr] = []

                deltapre_status[addr].append( DeltapreStat(tre.to_timestamp) )


            #yield prv, tre, crr
        prv = crr

    log("reporting...")
    count_active = 0
    count_inactive = 0
    with open(args.FN, "w") as f:
        for addr in deltapre_status:
            dpslist = deltapre_status[addr]
            for dps in dpslist:
                f.write("%s\t%d\t%d\t%d\n" % (addr,
                                              dps.count,
                                              dps.ts,
                                              1 if dps.expired else 0 ))
                if dps.count == 0:
                    count_inactive += 1
                else:
                    count_active += 1
    log("active address occurrences:" + str(count_active))
    log("inactive address occurrences:" + str(count_inactive))
    return

def op_viz():
    timestr="2014-04-06 7:30:00"
    st=calendar.timegm(time.strptime(timestr, fmt))
    print st


    eqset = EqSet()
    eqset.computeRepresentatives()

    pre,post= get_events_at_time(AS=2856,
                       tmin=calendar.timegm(time.strptime("2014-04-03 0:0:0", fmt)),
                       tmax=calendar.timegm(time.strptime("2014-04-08 0:0:0", fmt)),
                       eqset=eqset,
                       starttime=st,
                       window=unpomenodiunora)

    print correlation_graph_analysis.analyse_filtered_events(pre)
    print correlation_graph_analysis.analyse_filtered_events(post)

    gpre=graph_from_event_pairs(pre)
    gpost=graph_from_event_pairs(post)

    for g, label in [(gpre,"pre"),(gpost,"post")]:
        cliques=list(networkx.find_cliques(g))
        cliques.sort(key=len)
        cliques.reverse()
        maxclique=cliques[0]
        try:
            max2clique=cliques[1]
        except:
            max2clique=None

        for clique, maxlabel in [(maxclique, "max"), (max2clique, "max2")]:
            if not clique:
                continue
            msm_list_in_clique = map(lambda x: x[0], clique)
            most_common_msm_in_clique = max(set(msm_list_in_clique), key=msm_list_in_clique.count)

            print '--- ', label, ' ', maxlabel
            print "   destination", most_common_msm_in_clique, " appears ", msm_list_in_clique.count(most_common_msm_in_clique), 'out of', len(clique) , 'nodes'

            from collections import defaultdict
            nodestats=defaultdict(int)
            for v in clique:
                print '   ', v
                pprint(g.node[v]['events'], indent=4)
                path=next(iter(g.node[v]['events']))[ 'to_path' if label=='post' else 'from_path']
                for ip in set(path):
                    nodestats[ip]+=1

            listnodestats=nodestats.items()
            listnodestats.sort(key=lambda x: x[1])
            listnodestats.reverse()
            print "    first 3 most frequent ip's:", listnodestats[:3]
            q = "http://amarone.dia.uniroma3.it/tplay/client/leone/run_tplay.html?"
            q +="resource=" + str(most_common_msm_in_clique)
            q +="&starttime=" + str((st - 3600))
            q +="&endtime=" + str((st + 2*3600))
            q +="&selectedProbes=" + reduce( lambda x,y: x + "," + y,
                                             set(map(lambda x: str(x[1]), clique))
                                             )
            print "   ", q
        g2=networkx.relabel_nodes(g, {n: str(n) for n in g.nodes() }  ) # this makes a copy
        for n in g2:
            del g2.node[n]['events']
            del g2.node[n]['n']
        networkx.write_gml(g2, "graph_%s_%s.gml" % (timestr, label ) );




def op_lbsets():
    log("AS=%d starttime=%s endtime=%s" % (AS, starttime, endtime))


    if args.load:
        log("Loading load balancers from file: %s" % args.load )
        eqset= EqSet.load(file(args.load))
    else:
        g=routingAnalysisLB(
                            AS,
                            tmin,
                            tmax
                            )
        eqset = inferLB(g)
        eqset.computeRepresentatives()

    if args.save:
        eqset.save(file(args.save,'w'))

    f=sys.stdout

    tot=0
    for i in eqset.getsets():
        tot+=len(i)
    f.write('%d load balancers involving %d addresses\n' % (len(eqset.getsets()), tot
                                                            )
            )

    L=[ (rep, list(s)) for rep, s in eqset.getmapping().iteritems() ]
    L.sort(key=lambda x: x[0])
    for l in L:
        l[1].sort()

    for rep, s in L:
        if args.net:
            whoisinfo=unicode(whoisInetnum(rep),errors="replace")
            try:
                import socket
                socket.setdefaulttimeout(0.3)
                result=socket.gethostbyaddr(rep)
                name=result[0]
            except:
                name="(no name)"
        else:
            name=""
            whoisinfo=""
        ASnum, ASname= Ip2ASresolver.instance.getASInfo(rep)
        wi=whoisinfo.encode("ascii", errors="replace")
        asname = ASname if ASname else ""
        asname = asname.encode("ascii", errors="replace")
        f.write('%s %s %s %s %s\n'% (rep, name , wi, ASnum, asname))
        # try:
        # except :
        #     print(wi)
        #     print(ASname)
        #     raise
        L=list(s)
        L.sort()
        for ip in L:
            ASnum, ASname= Ip2ASresolver.instance.getASInfo(ip)
            if args.net:
                try:
                    result=socket.gethostbyaddr(ip)
                    name=result[0]
                    name+= reduce(lambda x,y: x+' '+y, result[1], '')
                except:
                    name="(no name)"
            else:
                name=""
            f.write('    %s %s %s\n'% (ip,  ASnum, name ))
            f.flush()
        f.write('\n')
        f.flush()


def op_lbreport():
    g=routingAnalysisLB(
                        AS,
                        tmin,
                        tmax
                        )
    reportLB(g, sys.stdout)
    sys.exit()



def op_traceroutes():
    if args.load:
        log("Loading load balancers from file: %s" % args.load )
        eqset= EqSet.load(file(args.load))
    else:
        eqset = EqSet()
        eqset.computeRepresentatives()

    assert args.probe 
    assert args.destination
 
    probe=args.probe
    dest=args.destination   
    f=sys.stdout

    cursor=(tr.find( {'prb_id': probe, 'msm_id': dest, "startTimestamp": {"$gte":tmin, "$lte": tmax } },
                    {"hops": 1, "startTimestamp":1, "_id":0})
                .sort("startTimestamp")
                )
    for crr in cursor:
        trouteNoLB= extract(crr,None)
        troute = extract(crr,eqset)
        s = time.strftime(fmt, time.gmtime(troute.timestamp)) +" ("+str(troute.timestamp)+")"
        
        sNoLB=s
        for ip in troute.path:
            AS = Ip2ASresolver.instance.getASInfo(ip)[0]
            s += "%17s_%-6s " % (ip,AS)
        for ip in trouteNoLB.path:
            AS = Ip2ASresolver.instance.getASInfo(ip)[0]
            sNoLB += "%17s_%-6s " % (ip,AS)
        f.write(str(s)+'\n')
        f.write(str(sNoLB)+'\n')
        f.write('\n')

def op_lbstat():
    log("Loading load balancers from file: %s" % args.load )
    eqset= EqSet.load(file(args.load))

    pairs = find_prb_dest_pairs_for_AS(AS)

    f=sys.stdout

    from collections import defaultdict
    stats = defaultdict(int)
    counttr=0
    uniqPaths = set()
    for dest, probe in pairs:
        cursor=(tr.find( {'prb_id': probe, 'msm_id': dest, "startTimestamp": {"$gte":tmin, "$lte": tmax } },
                        {"hops": 1, "startTimestamp":1, "_id":0})
                    .sort("startTimestamp")
                    )
        for crr in cursor:
            troute = extract(crr,eqset)
            counttr+=1
            uniqPaths.add(tuple(troute.path))
            howManyLB=0
            for hop in troute.path:
                if len(hop)>1 and hop[-1]=='*':
                    howManyLB+=1
            stats[howManyLB]+=1

    f.write('traceroute statistics (paths counted with their multiplicity)\n' )
    L=stats.items()
    L.sort()
    for k, v in L:
        f.write('%2d: %6d %5.1f%%\n' % (k,v, float(v)/counttr*100))
    f.flush()


    statsUniq=defaultdict(int)
    for path in uniqPaths:
        howManyLB=0
        for hop in path:
            if len(hop)>1 and hop[-1]=='*':
                howManyLB+=1
        statsUniq[howManyLB]+=1


    f.write('unique paths statistics (each distinct path is counted as one)\n' )
    L=statsUniq.items()
    L.sort()
    for k, v in L:
        f.write('%2d: %6d %5.1f%%\n' % (k,v, float(v)/len(uniqPaths)*100))
    f.flush()



def op_dbstat():
    """print min and max timestamps in traceroutes"""

    print "min"
    for i in tr.find( {}, {"startTimestamp":1}).sort("startTimestamp", ASCENDING ).limit(1):
        pprint(i)
        print time.strftime(fmt, time.gmtime(i['startTimestamp']))

    print "max"
    for i in tr.find( {}, {"startTimestamp":1}).sort("startTimestamp", DESCENDING ).limit(1):
        pprint(i)
        print time.strftime(fmt, time.gmtime(i['startTimestamp']))


    print "count traceroutes"
    print tr.find().count()


def op_changesstat():
    if args.load:
        log("Loading load balancers from file: %s" % args.load )
        eqset= EqSet.load(file(args.load))
    else:
        eqset = EqSet()
        eqset.computeRepresentatives()

    pairs = find_prb_dest_pairs_all()
        
    log("scanning transitions")
    
    transitions = 0 
    
    from collections import defaultdict
    numSharedIpDistr = defaultdict(int)   # defaults to 0

    for destination, probe in pairs:
        for frm, transition, to in getTrEvents(destination, probe, tmin, tmax, eqset):
            transitions += 1 

            s1 = set(transition.pathfrom) 
            s2 = set(transition.pathto)
            numOfSharedIPs = len(s1.intersection(s2))
            numSharedIpDistr[numOfSharedIPs] += 1
            
            if numOfSharedIPs>0 and args.printmultiple:
                print transition.pathfrom
                print transition.pathto
                print
                
    print "scanned total transitions", transitions
    dist = numSharedIpDistr.items()
    dist.sort()
    for n, q in dist :
        print n, q



def op_scratch():
    probes = db.command( { "distinct":"traceroute", "key": "msm_id", "query":{ } } )["values"]
    for i in probes: print i 
    sys.exit()


def init_argparser():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # parser.add_argument("--x",
    #                     action='store',
    #                     help="loads information aboud load balancers previously saved. Provide a filename as argument.",
    #                     metavar='FILENAME',
    #                     default='dummy.txt'
    #                     )

    parser.add_argument("--period",
                        action='store',
                        help="extension of the period YYYYMMDDHHMMSS-YYYYMMDDHHMMSS",
                        type=str,
                        default="20140117000000-20140701235959",
                        )

    parser.add_argument("--AS",
                        action='store',
                        help="number of autonomous system to inspect (TI: 3269, BT: 2856) .",
                        type=int,
                        default=0)

    parser.add_argument("--db",
                        action='store',
                        help="the name of the database to be accessed.",
                        type=str,
                        default="leone"
                        )

    subparsers = parser.add_subparsers(dest='op', help="The operation to be performed")

    subp = subparsers.add_parser('analysis', help='performs anomaly detection analysis by means of empathy.')

    subp.add_argument("--load",
                        action='store',
                        help="loads information aboud load balancers previously saved. Provide a filename as argument.",
                        metavar='FILENAME'
                        )
    subp.add_argument("--net",
                        help="Allows accessing whois and reverse DNS for more informative output.",
                        action='store_true',
                        default=False
                        )
    subp.add_argument("--threshold",
                        help="Set the thresold to dect a max clique in an empathy graph as an anomaly.",
                        action='store',
                        type=int,
                        default=5
                        )
    subp.add_argument("--outreport",
                        action='store',
                        type=str,
                        metavar='FILENAME',
                        default='report.txt',
                        help="Set the name of the output file where the report about detected anomalies is written."
                        )

    subp.add_argument("--regexp",
                        action='store',
                        type=str,
                        help="Produces in the report just the events that have as most common ip addresses those that have as description string (derived from whois, dns or AS description) matching the regular expression REGEXP."
                        )

    subp = subparsers.add_parser('great_analysis',
                                            help='performs anomaly detection analysis by means of the great algorithm.'
                                            )
    subp.add_argument("--threshold",
                        help="Set the threshold to detect a max clique in an empathy graph as an anomaly.",
                        action='store',
                        type=int,
                        default=5
                        )
    subp.add_argument("--net",
                        help="Allows accessing whois and reverse DNS for more informative output.",
                        action='store_true',
                        default=False
                        )
    subp.add_argument("--load",
                        action='store',
                        help="loads information aboud load balancers previously saved. Provide a filename as argument.",
                        metavar='FILENAME'
                        )
    subp.add_argument("--nowildcards",
                        help="Ignore events where identified IPs are only wildcards (*).",
                        action='store_true',
                        default=False
                        )

    subp.add_argument("--json",
                        help="Output as JSON.",
                        action='store_true',
                        default=False
                        )

    subp.add_argument("--path-details",
                        help="Add path details to each sd-pair of an event.",
                        action='store_true',
                        default=False
                        )

    subp.add_argument("--random-seed", 
                        help="A seed for the randomization of the order of the probes", 
                        action="store", 
                        default=False)

    subp.add_argument("--num-sdpairs", 
                      type=int,
                      help="The number of random sd-pairs to consider", 
                      action="store", 
                      default=False)

    subp.add_argument("--candidate-events-report",
                      metavar="FN",
                      type=str,
                      help="Consider the candidate events. This option dumps, in a file named FN, "
                           "one record for each candidate event. Fields are start (unix time), end (unix time), "
                           "IP, size of its scope (i.e. number of sd-pairs), seapartion in seconds from previous "
                           "CE form the same eIP (or None for the first).",
                      action="store",
                      default=None)

    subp = subparsers.add_parser("deltapreanalysis",
                        help="Count how many time an address occurring in delta^pre of a transition, "
                             "ending at t_end,"
                             "is observed in traceroutes that are recorded between t_end and t_end+T."
                               )

    subp.add_argument("T",
                        help="the extent the analysis looks into the future for occurence of an address.",
                        type=int,
                        action="store",
                        default=None)

    subp.add_argument("FN",
                      help="Write the output to a file named FN. Each line contains an address A, and a count "
                           "C (an integer), a timestamp, and a boolean in {0,1}. For each occurrence of any address A in "
                           "any deltapre that is different from '*' we report a record. "
                           "C counts the number of traceroutes containing A that appeard not later"
                           "than T seconds that the end of the transition of the deltapre. The "
                           "timestamp reported is the end timestamp of the transition. The flag is true if"
                           "the T seconds passed and at least a traceroute was processed that recognised "
                           "the occurrence as enough old to not consider it any longer.",
                      type=str,
                      action="store",
                      default=None)


    subp.add_argument("--load",
                      action='store',
                      help="loads information aboud load balancers previously saved. Provide a filename as argument.",
                      metavar='FILENAME'
                      )





    subparsers.add_parser('viz', help='provides detailed information for a specific instant of time')

    subparsers.add_parser('lbreport', help='report about internal state of the load balancers inference')

    subp = subparsers.add_parser('lbsets', help='provide load blanacers inference')
    subp.add_argument("--load",
                        action='store',
                        help="loads information aboud load balancers previously saved. Useful for getting a printout of what has been saved. Provide a filename as argument.",
                        metavar='FILENAME'
                        )
    subp.add_argument("--save",
                        action='store',
                        help="saves the load balancers computed by lbsets command for future loading. Provide a filename as argument.",
                        metavar='FILENAME'
                        )
    subp.add_argument("--net",
                        help="Allows accessing whois and reverse DNS for more informative output.",
                        action='store_true',
                        default=False
                        )


    subp  = subparsers.add_parser('traceroutes', help='print traceroutes taken from db with load balancer preprocessing made')
    subp.add_argument("--load",
                        action='store',
                        help="loads information aboud load balancers previously saved. Provide a filename as argument.",
                        metavar='FILENAME'
                        )
    subp.add_argument("--probe",
                        type=int,
                        action='store',
                        help="set the probe for the report",
                        metavar='PROBE_ID'
                        )

    subp.add_argument("--destination",
                        type=int,
                        action='store',
                        help="set the destination id for the report.",
                        metavar='DEST_ID'
                        )

    subp  = subparsers.add_parser('changesstat', help='Statistics about multiple distinct subsequence changes in traceroutes. Get delta pre and post according naive definition (see paper at ISCC2015) and look for intersection.')
    subp.add_argument("--load",
                        action='store',
                        help="loads information aboud load balancers previously saved. Provide a filename as argument. (REQUIRED)",
                        metavar='FILENAME'
                        )
    subp.add_argument("--printmultiple",
                        action='store_true',
                        help="print transactions with multiple distinct subsequences that change",
                        )


    subp  = subparsers.add_parser('lbstat', help='statistics about how many load balancer are traversed by traceroutes')
    subp.add_argument("--load",
                        action='store',
                        help="loads information aboud load balancers previously saved. Provide a filename as argument. (REQUIRED)",
                        metavar='FILENAME',
                        required= True
                        )

    subparsers.add_parser('dbstat', help='statistics about databases, in particular about collection traceroutes')


    subparsers.add_parser('scratch', help='executes scratch code')

    return parser


def computeGlobals():

    parser = init_argparser()
    args = parser.parse_args()
    log('arguments:'+str(args))

    AS=args.AS
    start_instant, end_instant = args.period.split('-')
    assert not args.op=="great_analysis" or (not args.random_seed or args.num_sdpairs)

    fmt1 = "%Y%m%d%H%M%S"
    tmin=calendar.timegm(time.strptime(start_instant, fmt1))
    tmax=calendar.timegm(time.strptime(end_instant, fmt1))
    starttime = time.strftime(fmt, time.gmtime(tmin))
    endtime = time.strftime(fmt, time.gmtime(tmax))

    log('tmin= %d (%s), tmax=%d (%s)' % (tmin, starttime,
                                         tmax, endtime) )
    client = MongoClient()
    db=client.__getitem__(args.db)
    tr=db.traceroute

    return args, AS, tmin, tmax, starttime, endtime, client, db, tr


# set golbal variables

args, AS, tmin, tmax, starttime, endtime, client, db, tr = computeGlobals()

#initialise ip2AS resolver
Ip2ASresolver.instance=Ip2ASresolver()

# call the op_* function specified by args.op
globals().__getitem__('op_'+args.op)()


    

    
    
    
    
