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

def asn_name_query(asn):
    if asn == None:
        asn = 3701
    if 64512 <= asn <= 65534:
        return("RFC6996 - Private Use ASN")
    else:
        # query = 'as' + str(asn) + '.asn.cymru.com'
        # resolver = dns.resolver.Resolver()
        # resolver.timeout = 10
        # resolver.lifetime = 1
        try:
            query = 'as' + str(asn) + '.asn.cymru.com'
            #print(query)
            resolver = dns.resolver.Resolver()
            #print(resolver)
            answers = resolver.query(query, 'TXT')
            #print(answers)
            for rdata in answers:
                #print(rdata)
                return(str(rdata).split("|")[-1].split(",",2)[0].strip())
                # for txt_string in rdata.strings:
                #     print(txt_string)
                #     return(txt_string.split("|")[-1].split(",", 2)[0].strip())
        except:
            return("(DNS Error)")

def reverse_dns_query(ip):
    # resolver.timeout = 1
    # resolver.lifetime = 1
    try:
        addr = dns.reversename.from_address(str(ip))
        #return(addr)
        resolver = dns.resolver.Resolver()
        # resolver.timeout = 1
        # resolver.lifetime = 1
        # #print(str(resolver.query(addr,"PTR")[0])[:-1])
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
    client = MongoClient()
    db = client.bgp
    as_path_counter = 0

    all = db.bgp.find()
    for prefix in all:
        try:
            as_path_counter += len(set(prefix['as_path']))
        except:
            pass
    print(round(as_path_counter/all.count(), 3))


def top_peers(count):
    client = MongoClient()
    db = client.bgp
    top_peers_dict = {}
    peers = db.bgp.distinct("next_hop_asn")

    for peer in peers:
        prefixes = db.bgp.find({"next_hop_asn": peer})
        top_peers_dict[peer] = prefixes.count()
    top_n = take(count, sorted(top_peers_dict.items(), key=lambda x: x[1], reverse=True))
    for asn in top_n:
        print("%d - %d - %s" % (asn[1], asn[0], asn_name_query(asn[0])))

def ipv4_cidr_breakdown():
    client = MongoClient()
    db = client.bgp
    all_prefixes = db.bgp.find()
    ipv4_list = []
    ipv6_list = []


    for prefix in all_prefixes:
        if prefix['ip_version'] == 4:
            ipv4_list.append(int(prefix['prefix'].split('/',1)[1]))
        if prefix['ip_version'] == 6:
            ipv6_list.append(int(prefix['prefix'].split('/',1)[1]))

    ipv4_count = list(Counter(ipv4_list).items())
    print("### IPv4 CIDR Count ###")
    for mask, count in ipv4_count:
        print("Mask: /%d - Count: %d" % (mask, count))
    print()
    ipv6_count = list(Counter(ipv6_list).items())
    print("### IPv6 CIDR Count ###")
    for mask, count in ipv6_count:
        print("Mask: /%d - Count: %d" % (mask, count))



avg_as_path_length()
top_peers(10)
ipv4_cidr_breakdown()


# client = MongoClient()
# db = client.bgp
#
# # cursor = db.restaurants.find({"borough": "Manhattan"})
# #
# # for document in cursor:
# #     print(document)
#
# peer_asns = db.bgp.distinct("next_hop_asn")
# next_hop_ips = db.bgp.distinct("nexthop")
# origin_asns =  db.bgp.distinct("origin_as")
# google = db.bgp.find({"next_hop_asn": 15169})
# isp = db.bgp.find({"origin_as": 15169})
# communities = db.bgp.distinct("communities")
# cidr = db.bgp.find()
#
# ip = '157.246.0.0'
# subnet_mask = 24
#
# print("Total Prefixes: ", db.bgp.count())
# print("Total Peers: ", len(peer_asns))
# print("Next Hop IP Address: ", len(next_hop_ips))
# print("Origin ASNs: ", len(origin_asns))
#
# #print("Avg AS Path Length:")
# #print("ISP:", isp)
# #
# # for comm in communities:
# #     print('%s - %s' % (comm, db.bgp.find({'communities': {'$regex' : comm}}).count()))
# #
# # cidr_list = []
# # bads_list = []
# # for prefix in cidr:
# #     if prefix['ip_version'] == 4:
# #         cidr_list.append(int(prefix['prefix'].split('/',1)[1]))
# #         if int(prefix['prefix'].split('/',1)[1]) > 24:
# #             bads_list.append('%d : %s' % (int(prefix['origin_as']), prefix['prefix']))
# #             # print('%s : %s' % (prefix['origin_as'], prefix['prefix']))
# #         # print(Counter(cidr_list))
# #
# # bads_list.sort()
# # for blah in bads_list:
# #     print(blah)
# # print(bads_list)
# # # for mask in cidr_list:
# # #     print('%s' : '%d' % (mask, ))
# # # print(Counter(cidr_list).keys())
# # # print(Counter(cidr_list).values())
# # #print(find_network(ip, subnet_mask))
# # # print("Google: ")
# # #for prefix in isp:
# #     #print(prefix)
# # #    print(asn_name_query(prefix['origin_as']))
# #
# # # for ip in next_hop_ips:
# # #     print(reverse_dns_query(ip))
# # # for peer in peer_asns:
# # #     print(str(peer) + ' - ' + asn_name_query(peer) + ": ", db.bgp.count({"next_hop_asn": peer}))
# #
# #
# # # Create Functions for the following:
# # # - Avg as_path (should give a good representation about overall connectivity)
# # # - IPv4 Netmask distribution and count per
# # # - IPv6 Netmask distribution and count per
