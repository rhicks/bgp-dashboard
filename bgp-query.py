#! /usr/bin/env python3

import json
import pymongo
from pymongo import MongoClient
import dns.resolver
import ipaddress
from collections import Counter
from itertools import islice

def take(n, iterable):
    "Return first n items of the iterable as a list"
    return list(islice(iterable, n))

def db_connect():
    client = MongoClient()
    return(client.bgp)

def asn_name_query(asn):
    if asn == None:
        asn = 3701
    if 64512 <= asn <= 65534:
        return("RFC6996 - Private Use ASN")
    else:
        try:
            query = 'as' + str(asn) + '.asn.cymru.com'
            resolver = dns.resolver.Resolver()
            answers = resolver.query(query, 'TXT')
            for rdata in answers:
                return(str(rdata).split("|")[-1].split(",",2)[0].strip())
        except:
            return("(DNS Error)")

def reverse_dns_query(ip):
    try:
        addr = dns.reversename.from_address(str(ip))
        resolver = dns.resolver.Resolver()
        return str(resolver.query(addr,"PTR")[0])[:-1]
    except:
        return("(DNS Error)")

def find_network(ip, netmask):
    network = str(ipaddress.ip_network(ipaddress.ip_address(ip)).supernet(new_prefix=netmask))
    print(network)
    result = db.bgp.find_one({"prefix": network})
    if result:
        return(result)
    elif netmask == 0:
        return(None)
    else:
        return(find_network(ip, netmask-1))

def avg_as_path_length():
    db = db_connect()
    as_path_counter = 0

    all = db.bgp.find()
    for prefix in all:
        try:
            as_path_counter += len(set(prefix['as_path']))
        except:
            pass
    path_length = round(as_path_counter/all.count(), 3)
    return json.dumps({'avg_as_path_length': path_length})


def top_peers(count):
    db = db_connect()
    top_peers_dict = {}
    peers = db.bgp.distinct("next_hop_asn")
    json_data = []

    for peer in peers:
        prefixes = db.bgp.find({"next_hop_asn": peer})
        top_peers_dict[peer] = prefixes.count()
    top_n = take(count, sorted(top_peers_dict.items(), key=lambda x: x[1], reverse=True))
    for asn in top_n:
        json_data.append({
            'asn': asn[0],
            'count': asn[1],
            'name': asn_name_query(asn[0])})
    return(json.dumps(json_data, indent=2))


def cidr_breakdown():
    db = db_connect()
    all_prefixes = db.bgp.find()
    ipv4_list = []
    ipv6_list = []
    json_data = []
    bads_list = []

    for prefix in all_prefixes:
        if prefix['ip_version'] == 4:
            ipv4_list.append(int(prefix['prefix'].split('/',1)[1]))
            if int(prefix['prefix'].split('/',1)[1]) > 24:
                bads_list.append({
                'origin_as': int(prefix['origin_as']),
                'prefix': prefix['prefix']})
        if prefix['ip_version'] == 6:
            ipv6_list.append(int(prefix['prefix'].split('/',1)[1]))

    ipv4_count = list(Counter(ipv4_list).items())
    ipv6_count = list(Counter(ipv6_list).items())

    for mask, count in ipv4_count:
        json_data.append({
            'mask': mask,
            'count': count,
            'ip_version': 4})
    for mask, count in ipv6_count:
        json_data.append({
            'mask': mask,
            'count': count,
            'ip_version': 6})

    cidr_list = json.dumps(json_data, indent=2)
    bad_list  = json.dumps(bads_list, indent=2)

    return(cidr_list, bad_list)

def communities_count():
    db = db_connect()
    communities = db.bgp.distinct("communities")
    json_data = []

    for comm in communities:
        json_data.append({
            'community': comm,
            'count': db.bgp.find({'communities': {'$regex' : comm}}).count()})

    return(json.dumps(json_data, indent=2))


print(avg_as_path_length())
print(top_peers(10))
print(cidr_breakdown()[0])
print(communities_count())
