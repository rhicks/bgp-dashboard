#! /usr/bin/env python3

import json
import pymongo
from pymongo import MongoClient

client = MongoClient()
db = client.bgp

from datetime import datetime
with open('log/log.json', 'r') as f:
     data = json.load(f)

prefixes = []

for k, v in data.items():
    prefix = None
    nexthop = None
    as_path = None
    next_hop_asn = None
    origin_as = None
    prefix = v[0]['nlri']['prefix']
    for attribute in v[0]['attrs']:
        if attribute['type'] == 3:
            nexthop = attribute['nexthop']
        elif attribute['type'] == 2:
            try:
                as_path = attribute['as_paths'][0]['asns']
                next_hop_asn = attribute['as_paths'][0]['asns'][0]
                origin_as = attribute['as_paths'][0]['asns'][-1]
            except:
                pass
    prefixes.append({'prefix': prefix, 'nexthop': nexthop, 'as_path': as_path, 'next_hop_asn': next_hop_asn, 'origin_as': origin_as})

db.bgp.drop()
result = db.bgp.insert_many(prefixes)

#cursor = db.restaurants.find({"borough": "Manhattan"})
cursor = db.bgp.find({})
print(db.bgp.count())

# for document in cursor:
#     print(document)
