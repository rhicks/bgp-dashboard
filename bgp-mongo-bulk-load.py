#! /usr/bin/env python

import json
from pymongo import MongoClient
import fileinput
import ipaddress

client = MongoClient('mongo')
db = client.bgp
db.bgp.drop()
db.bgp.create_index('next_hop_asn')
db.bgp.create_index('prefix')
db.bgp.create_index('origin_as')


def build_object(prefix, v):
    nexthop = None
    as_path = None
    next_hop_asn = None
    origin_as = None
    med = None
    local_pref = None
    withdrawal = None
    ip_version = ipaddress.ip_address(prefix.split('/', 1)[0]).version
    communities = []
    for attribute in v[0]['attrs']:
        if attribute['type'] == 3:
            nexthop = attribute['nexthop']
        elif attribute['type'] == 14:
            nexthop = attribute['nexthop']
        elif attribute['type'] == 2:
            try:
                as_path = attribute['as_paths'][0]['asns']
            except:
                as_path = None
            try:
                next_hop_asn = attribute['as_paths'][0]['asns'][0]
            except:
                next_hop_asn = None
            try:
                origin_as = attribute['as_paths'][0]['asns'][-1]
            except:
                origin_as = None
        elif attribute['type'] == 7:
            try:
                origin_as = attribute['as']
            except:
                origin_as = None
        elif attribute['type'] == 4:
            try:
                med = attribute['metric']
            except:
                med = None
        elif attribute['type'] == 8:
            try:
                communities = []
                for number in attribute['communities']:
                    communities.append(str(int(bin(number)[:-16], 2)) + ":" +
                                       str(int(bin(number)[-16:], 2)))
            except:
                communities = []
        elif attribute['type'] == 5:
            try:
                local_pref = attribute['value']
            except:
                local_pref = None
    if 'withdrawal' in v[0]:
        withdrawal = v[0]['withdrawal']
    else:
        withdrawal = None
    if 'age' in v[0]:
        timestamp = v[0]['age']
    else:
        timestamp = None

    data = {'prefix': prefix,
            'nexthop': nexthop,
            'as_path': as_path,
            'next_hop_asn': next_hop_asn,
            'origin_as': origin_as,
            'med': med,
            'local_pref': local_pref,
            'withdrawal': withdrawal,
            'ip_version': ip_version,
            'communities': communities,
            'timestamp': timestamp}

    return(data)


def mongo_update(data):
    if data['withdrawal'] is True:
        result = db.bgp.delete_one({"prefix": data['prefix']})
        print('Del: %s' % (data['prefix']))
    else:
        result = db.bgp.update({"prefix": data['prefix']}, data, upsert=True)
        if result['nModified'] == 0:
            print('Add: %s' % (data['prefix']))
        elif result['nModified'] == 1:
            print('Mod: %s' % (data['prefix']))
        else:
            print('???: %s' % (data['prefix']))


for line in fileinput.input():
    v = json.loads(line)
    prefix = None
    if v[0]['attrs'][0]['type'] == 14:
        for prefix in v[0]['attrs'][0]['value']:
            mongo_update(build_object(prefix['prefix'], v))
    else:
        prefix = v[0]['nlri']['prefix']
        mongo_update(build_object(prefix, v))
