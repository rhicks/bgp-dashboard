#! /usr/bin/env python

import json
from pymongo import MongoClient
import fileinput
import ipaddress
import sys


def db_connect():
    """Return a connection to the Mongo Database."""
    client = MongoClient(host='mongo')
    return client.bgp


def initialize_database(db):
    """Drop existing data and create indexes"""
    db.bgp.drop()
    db.bgp.create_index('prefix')
    db.bgp.create_index('next_hop_asn')
    db.bgp.create_index('origin_as')
    db.bgp.create_index('nexthop')
    db.bgp.create_index('as_path')
    db.bgp.create_index('med')
    db.bgp.create_index('local_pref')
    db.bgp.create_index('withdrawal')
    db.bgp.create_index('ip_version')
    db.bgp.create_index('communities')
    db.bgp.create_index('prefix')
    

def build_json_update_entry(update_entry):
    """Take individual update entries from GoBGP and build json objects to be
    consumed as MonogoDB entries."""
    nexthop = as_path = next_hop_asn = origin_as = med = local_pref = withdrawal = None
    communities = []
    prefix = update_entry['nlri']['prefix']
    ip_version = ipaddress.ip_address(prefix.split('/', 1)[0]).version
    for attribute in update_entry['attrs']:
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
        else:
            pass
    if 'withdrawal' in update_entry:
        withdrawal = update_entry['withdrawal']
    else:
        withdrawal = None
    if 'age' in update_entry:
        timestamp = update_entry['age']
    else:
        timestamp = None

    return {'prefix': prefix,
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


def mongo_update(data, db):
    """Update the mongodb with json BGP update objects."""
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


def main():
    """Read GoBGP RIB JSON update lists from stdin and send individual entries
    to be parsed and fed into Mongo."""
    db = db_connect()
    initialize_database(db)
    for line in fileinput.input():
        try:
            update_list = json.loads(line)
            for update_entry in update_list:
                if 'error' in update_entry:
                    pass
                else:
                    mongo_update(build_json_update_entry(update_entry), db)
        except Exception as err:
            print(err)
            pass


if __name__ == "__main__":
    sys.exit(main())
