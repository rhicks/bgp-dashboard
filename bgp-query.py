#! /usr/bin/env python3

import json
import pymongo
from pymongo import MongoClient
import dns.resolver


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
            resolver = dns.resolver.Resolver()
            answers = resolver.query(query, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    return(txt_string.split('|')[-1].split(",", 2)[0].strip())
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

client = MongoClient()
db = client.bgp

# cursor = db.restaurants.find({"borough": "Manhattan"})
#
# for document in cursor:
#     print(document)

peer_asns = db.bgp.distinct("next_hop_asn")
next_hop_ips = db.bgp.distinct("nexthop")
origin_asns =  db.bgp.distinct("origin_as")
google = db.bgp.find({"next_hop_asn": 15169})

print("Total Prefixes: ", db.bgp.count())
print("Total Peers: ", len(peer_asns))
print("Next Hop IP Address: ", len(next_hop_ips))
print("Origin ASNs: ", len(origin_asns))
print("Google: ")
for prefix in google:
    print(prefix)
# for ip in next_hop_ips:
#     print(reverse_dns_query(ip))
# for peer in peer_asns:
#     print(str(peer) + ' - ' + asn_name_query(peer) + ": ", db.bgp.count({"next_hop_asn": peer}))
