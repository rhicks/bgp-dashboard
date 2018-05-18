#! /usr/bin/env python3

import sys
import json
import bgp_attributes as BGP
from pymongo import MongoClient
import pymongo
from copy import copy
from datetime import datetime
import ipaddress
import logging
# logging.basicConfig(level=logging.CRITICAL)
# logging.basicConfig(level=logging.DEBUG)

# DEFAULTS - UPDATE ACCORDINGLY
MAX_PREFIX_HISTORY = 100  # None = unlimited (BGP flapping will likely kill DB if unlimited)


def db_connect(host='mongodb'):
    """Return a connection to the Mongo Database."""
    client = MongoClient(host=host)
    return client.bgp


def initialize_database(db):
    """Create indxes, and if the db contains any entries set them all to 'active': False"""
    # db.bgp.drop()
    db.bgp.create_index('nexthop')
    db.bgp.create_index('nexthop_asn')
    db.bgp.create_index([('nexthop', pymongo.ASCENDING), ('active', pymongo.ALL)])
    db.bgp.create_index([('nexthop_asn', pymongo.ASCENDING), ('active', pymongo.ALL)])
    db.bgp.create_index([('ip_version', pymongo.ASCENDING), ('active', pymongo.ALL)])
    db.bgp.create_index([('origin_asn', pymongo.ASCENDING), ('ip_version', pymongo.ASCENDING), ('active', pymongo.ALL)])
    db.bgp.create_index([('communities', pymongo.ASCENDING), ('active', pymongo.ALL)])
    db.bgp.create_index([('as_path.1', pymongo.ASCENDING), ('nexthop_asn', pymongo.ASCENDING), ('active', pymongo.ALL)])
    db.bgp.update_many(
        {"active": True},  # Search for
        {"$set": {"active": False}})  # Replace with


def get_update_entry(line):
    """Read output from GoBGP from stdin and return a update entry *dict*"""
    try:
        update_list = json.loads(line)
        for update_entry in update_list:
            if 'error' in update_entry:
                return None
            else:
                return(update_entry)
    except Exception as err:
        logging.error("Error in get_update_entry(line):", err)
        return None


def compare_prefixes(new, old):
    """ignore history, age, and active state, then compare prefix objects"""
    new['history'] = new['age'] = new['active'] = None
    old['history'] = old['age'] = old['active'] = None
    if new == old:
        return True
    else:
        return False


def community_32bit_to_string(number):
    """Given a 32bit number, convert to standard bgp community format XXX:XX"""
    if number is not 0:
        return f'{int(bin(number)[:-16], 2)}:{int(bin(number)[-16:], 2)}'  # PEP 498


def build_json(update_entry):
    """Given an update entry from GoBGP, set the BGP attribue types as a
    key/value dict and return"""
    update_json = {  # set defaults
        '_id': update_entry['nlri']['prefix'],
        'ip_version': ipaddress.ip_address(update_entry['nlri']['prefix'].split('/', 1)[0]).version,
        'origin_asn': None,
        'nexthop': None,
        'nexthop_asn': None,
        'as_path': [],
        'med': 0,
        'local_pref': 0,
        'communities': [],
        'route_origin': None,
        'atomic_aggregate': None,
        'aggregator_as': None,
        'aggregator_address': None,
        'originator_id': None,
        'cluster_list': [],
        'withdrawal': False,
        'age': 0,
        'active': True,
        'history': []
    }
    for attribute in update_entry['attrs']:
        if attribute['type'] == BGP.ORIGIN:
            update_json['route_origin'] = BGP.ORIGIN_CODE[attribute['value']]
        if attribute['type'] == BGP.AS_PATH:
            try:
                update_json['as_path'] = attribute['as_paths'][0]['asns']
                update_json['nexthop_asn'] = update_json['as_path'][0]
                update_json['origin_asn'] = update_json['as_path'][-1]
            except Exception:
                logging.debug(f'Error processing as_path: {attribute}')
                logging.debug(f'Error processing as_path: {update_json["_id"]}')
        if attribute['type'] == BGP.NEXT_HOP:
            update_json['nexthop'] = attribute['nexthop']
        if attribute['type'] == BGP.MULTI_EXIT_DISC:
            try:
                update_json['med'] = attribute['metric']
            except Exception:
                logging.debug(f'Error processing med: {attribute}')
        if attribute['type'] == BGP.LOCAL_PREF:
            try:
                update_json['local_pref'] = attribute['value']
            except Exception:
                logging.debug(f'Error processing local_pref: {attribute}')
        if attribute['type'] == BGP.ATOMIC_AGGREGATE:
            update_json['atomic_aggregate'] = True
        if attribute['type'] == BGP.AGGREGATOR:
            update_json['aggregator_as'] = attribute['as']
            update_json['aggregator_address'] = attribute['address']
        if attribute['type'] == BGP.COMMUNITY:
            try:
                for number in attribute['communities']:
                    update_json['communities'].append(community_32bit_to_string(number))
            except Exception:
                logging.debug(f'Error processing communities: {attribute}')
        if attribute['type'] == BGP.ORIGINATOR_ID:
            update_json['originator_id'] = attribute['value']
        if attribute['type'] == BGP.CLUSTER_LIST:
            update_json['cluster_list'] = attribute['value']
        if attribute['type'] == BGP.MP_REACH_NLRI:
            update_json['nexthop'] = attribute['nexthop']
        if attribute['type'] == BGP.MP_UNREACH_NLRI:
            logging.debug(f'Found MP_UNREACH_NLRI: {attribute}')
        if attribute['type'] == BGP.EXTENDED_COMMUNITIES:
            logging.debug(f'Found EXTENDED_COMMUNITIES: {attribute}')
    if 'withdrawal' in update_entry:
        update_json['withdrawal'] = update_entry['withdrawal']
        update_json['active'] = False
    if 'age' in update_entry:
        update_json['age'] = datetime.fromtimestamp(update_entry['age']).strftime('%Y-%m-%d %H:%M:%S ') + 'UTC'

    return update_json


def update_prefix(prefix_from_gobgp, prefix_from_database):
    if compare_prefixes(copy(prefix_from_gobgp), copy(prefix_from_database)):
        prefix_from_gobgp['active'] = True  # flip the active state to true
    else:  # diff between prefix_from_gobgp and prefix_from_database: update history
        history_list = prefix_from_database['history']
        del prefix_from_database['active']  # delete house keeping keys from history objects
        del prefix_from_database['history']
        if not history_list:  # no history: create some
            prefix_from_gobgp['history'].append(prefix_from_database)
        else:  # existing history: append to history list
            history_list.insert(0, prefix_from_database)  # insert on top of list, index 0
            prefix_from_gobgp['history'] = history_list[:MAX_PREFIX_HISTORY]  # trim the history list if MAX is set
    return prefix_from_gobgp


def main():
    db = db_connect()
    initialize_database(db)
    for line in sys.stdin:
        prefix_from_gobgp = build_json(get_update_entry(line))
        prefix_from_database = db.bgp.find_one({'_id': prefix_from_gobgp['_id']})
        if prefix_from_database:
            updated_prefix = update_prefix(prefix_from_gobgp, prefix_from_database)
            db.bgp.update({"_id": prefix_from_database['_id']}, updated_prefix, upsert=True)
        else:
            db.bgp.update({"_id": prefix_from_gobgp['_id']}, prefix_from_gobgp, upsert=True)


if __name__ == "__main__":
    sys.exit(main())
