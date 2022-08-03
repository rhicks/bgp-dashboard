#! /usr/bin/env python3

import sys
import ipaddress
import logging
import json
import bgp_attributes as BGP
from datetime import datetime
import psycopg

db_server = "postgres"
db_name = "bgp_data"
db_table = "prefix"

def community_32bit_to_string(number):
    """Given a 32bit number, convert to standard bgp community format XXX:XX"""
    if number != 0:
        return f'{int(bin(number)[:-16], 2)}:{int(bin(number)[-16:], 2)}'  # PEP 498


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


def initialize_update_entry(update_entry):
    update_json = {  # set defaults
        'prefix': update_entry['nlri']['prefix'],
        'ip_version': ipaddress.ip_address(update_entry['nlri']['prefix'].split('/', 1)[0]).version,
        'origin_asn': None,
        'nexthop': None,
        'nexthop_asn': None,
        'as_path': [],
        'as_path_length': 0,
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
        'source_id': None,
        'neighbor_id': None
    }
    return update_json


def update_origin(update_json, attribute):
    if attribute['type'] == BGP.ORIGIN:
        update_json['route_origin'] = BGP.ORIGIN_CODE[attribute['value']]
    return update_json


def update_as_path(update_json, attribute):
    if attribute['type'] == BGP.AS_PATH:
        try:
            update_json['as_path'] = attribute['as_paths'][0]['asns']
            update_json['nexthop_asn'] = update_json['as_path'][0]
            update_json['origin_asn'] = update_json['as_path'][-1]
            update_json['as_path_length'] = attribute['as_paths'][0]['num']
        except Exception:
            logging.debug(f'Error processing as_path: {attribute}')
            logging.debug(f'Error processing as_path: {update_json["_id"]}')
    return update_json


def update_next_hop(update_json, attribute):
    if attribute['type'] == BGP.NEXT_HOP:
        update_json['nexthop'] = attribute['nexthop']
    return update_json


def update_med(update_json, attribute):
    if attribute['type'] == BGP.MULTI_EXIT_DISC:
        try:
            update_json['med'] = attribute['metric']
        except Exception:
            logging.debug(f'Error processing med: {attribute}')
    return update_json


def update_local_pref(update_json, attribute):
    if attribute['type'] == BGP.LOCAL_PREF:
        try:
            update_json['local_pref'] = attribute['value']
        except Exception:
            logging.debug(f'Error processing local_pref: {attribute}')
    return update_json


def update_atomic_agg(update_json, attribute):
    if attribute['type'] == BGP.ATOMIC_AGGREGATE:
        update_json['atomic_aggregate'] = True
    return update_json


def update_agggregator(update_json, attribute):
    if attribute['type'] == BGP.AGGREGATOR:
        update_json['aggregator_as'] = attribute['as']
        update_json['aggregator_address'] = attribute['address']
    return update_json


def update_communities(update_json, attribute):
    if attribute['type'] == BGP.COMMUNITY:
        try:
            for number in attribute['communities']:
                update_json['communities'].append(community_32bit_to_string(number))
        except Exception:
            logging.debug(f'Error processing communities: {attribute}')
    return update_json


def update_originator_id(update_json, attribute):
    if attribute['type'] == BGP.ORIGINATOR_ID:
        update_json['originator_id'] = attribute['value']
    return update_json


def update_cluster_list(update_json, attribute):
    if attribute['type'] == BGP.CLUSTER_LIST:
        update_json['cluster_list'] = attribute['value']
    return update_json


def update_mp_reach_nlri(update_json, attribute):
    if attribute['type'] == BGP.MP_REACH_NLRI:
        update_json['nexthop'] = attribute['nexthop']
    return update_json


def update_mp_unreach_nlri(update_json, attribute):
    if attribute['type'] == BGP.MP_UNREACH_NLRI:
        logging.debug(f'Found MP_UNREACH_NLRI: {attribute}')
    return update_json


def update_extended_communites(update_json, attribute):
    if attribute['type'] == BGP.EXTENDED_COMMUNITIES:
        logging.debug(f'Found EXTENDED_COMMUNITIES: {attribute}')
    return update_json


def update_source_id(update_json, update_entry):
    if update_entry['source-id']:
        update_json['source_id'] = update_entry['source-id']
    return update_json


def update_neighbor_ip(update_json, update_entry):
    if 'neighbor-ip' in update_entry:
        update_json['neighbor_ip'] = update_entry['neighbor-ip']
    return update_json


def set_attributes(update_json, update_entry):
    for attribute in update_entry['attrs']:
        update_json = update_origin(update_json, attribute)
        update_json = update_as_path(update_json, attribute)
        update_json = update_next_hop(update_json, attribute)
        update_json = update_med(update_json, attribute)
        update_json = update_local_pref(update_json, attribute)
        update_json = update_atomic_agg(update_json, attribute)
        update_json = update_agggregator(update_json, attribute)
        update_json = update_communities(update_json, attribute)
        update_json = update_originator_id(update_json, attribute)
        update_json = update_cluster_list(update_json, attribute)
        update_json = update_mp_reach_nlri(update_json, attribute)
        update_json = update_mp_unreach_nlri(update_json, attribute)
        update_json = update_extended_communites(update_json, attribute)
    update_json = update_source_id(update_json, update_entry)
    update_json = update_neighbor_ip(update_json, update_entry)
    if 'withdrawal' in update_entry:
        update_json['withdrawal'] = update_entry['withdrawal']
        update_json['active'] = False
    if 'age' in update_entry:
        update_json['age'] = datetime.fromtimestamp(update_entry['age']).strftime('%Y-%m-%d %H:%M:%S ') + 'UTC'
    return update_json


def build_json(update_entry):
    update_json = initialize_update_entry(update_entry)
    return set_attributes(update_json, update_entry)


def insert_into_sql(con, prefix_from_gobgp):
    con.execute('''
              INSERT into prefix
              (prefix, age, best, origin, as_path, next_hop,
              local_pref, communities, originator_id,
              cluster_list, stale, source_id, neighbor_ip,
              med, withdrawal, ip_version, active)
              VALUES
              (%(prefix)s, %(age)s, %(best)s, %(origin)s, %(as_path)s, %(next_hop)s,
              %(local_pref)s, %(communities)s, %(originator_id)s,
              %(cluster_list)s, %(stale)s, %(source_id)s, %(neighbor_ip)s,
              %(med)s, %(withdrawal)s, %(ip_version)s, %(active)s)
              ON CONFLICT (prefix)
              DO UPDATE
              SET (prefix, age, best, origin, as_path, next_hop,
              local_pref, communities, originator_id,
              cluster_list, stale, source_id, neighbor_ip,
              med, withdrawal, ip_version, active) = ROW(EXCLUDED.*);
              ''',
              {
                'prefix': prefix_from_gobgp['prefix'],
                'age': prefix_from_gobgp['age'],
                'best': False,
                'origin': prefix_from_gobgp['origin_asn'],
                'as_path': prefix_from_gobgp['as_path'],
                'next_hop': prefix_from_gobgp['nexthop'],
                'local_pref': prefix_from_gobgp['local_pref'],
                'communities': prefix_from_gobgp['communities'],
                'originator_id': prefix_from_gobgp['originator_id'],
                'cluster_list': prefix_from_gobgp['cluster_list'],
                'stale': False,
                'source_id': prefix_from_gobgp['source_id'],
                'neighbor_ip': prefix_from_gobgp['neighbor_ip'],
                'med': prefix_from_gobgp['med'],
                'withdrawal': prefix_from_gobgp['withdrawal'],
                'ip_version': prefix_from_gobgp['ip_version'],
                'active': prefix_from_gobgp['active']
              })
    return None

def db_connect(host=db_server, db=None):
    """Return a connection to the Database."""
    if db != None:
        connection_string = "host=" + host + " dbname=" + db
    else:
        connection_string = "host=" + host

    con = psycopg.connect(conninfo = connection_string, autocommit=True)
    return con

def create_db(db_name=db_name):
    try:
        sql_command = "CREATE database " + db_name
        con = db_connect()
        con.execute(sql_command)
        print("DB Created")
        con.close()
    except psycopg.errors.DuplicateDatabase:
        print("DB Already Exists")
        con.close()

def create_tables():
    sql_command = '''
    CREATE TABLE prefix
    (
        prefix cidr UNIQUE,
        age timestamp,
        best boolean,
        origin int,
        as_path int[],
        next_hop inet,
        local_pref int,
        communities varchar[],
        originator_id inet,
        cluster_list inet[],
        stale boolean,
        source_id inet,
        neighbor_ip inet,
        med int,
        withdrawal boolean,
        ip_version int,
        active boolean
    );'''
    con = db_connect(db_server, db_name)
    try:
        con.execute(sql_command)
        print("Table Created")
    except psycopg.errors.DuplicateTable:
        print("Table Exists")

def database_setup():
    create_db()
    create_tables()
    return db_connect(db_server, db_name)

def is_prefix_in_db(con, prefix):
    sql_command = "SELECT EXISTS (select prefix from prefix where prefix=\'%s\');" % (prefix)
    cursor = con.execute(sql_command)
    data = cursor.fetchone()[0]
    return data
    # return result.fetchone()[0] is not None


def main():
    con = database_setup()
    for line in sys.stdin:
        prefix_from_gobgp = build_json(get_update_entry(line))
        # if is_prefix_in_db(con, prefix_from_gobgp['prefix']):
        #     print("FOUND")
        # else:
        #     print("NOFOUND")
        # insert any new prefixes into the DB
        # update any existing prefixes
        insert_into_sql(con, prefix_from_gobgp)


if __name__ == "__main__":
    sys.exit(main())
