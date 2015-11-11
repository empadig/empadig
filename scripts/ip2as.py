import pymongo
import sys

class Ip2As:
    def __init__(self, db_name):
        self._map = {}
        client = pymongo.MongoClient()
        db = client[db_name]
        it = db.ip2as.find({}, {"_id":0, "address":1, "as_numbers":1})
        for record in it:
            assert len(record['as_numbers']) <= 1
            if len(record['as_numbers']) == 0:
                continue
            ip = record['address']
            as_number = record['as_numbers'][0]['asn']
            as_name = record['as_numbers'][0]['holder']
            assert not self._map.has_key(ip)
            self._map[ip] = (as_number, as_name)

    def get(self, ip):
        # strip trailing '*' off, if any
        if len(ip) > 1 and ip[-1] == "*": 
            ip = ip[:-1]
        try:
            return self._map[ip]
        except:
            return (None, None)
