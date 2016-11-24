#! /usr/bin/env python3

import json
import pymongo
from pymongo import MongoClient
import dns.resolver
import ipaddress


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
isp = db.bgp.find({"origin_as": 15169})

ip = '157.246.0.0'
subnet_mask = 24

print("Total Prefixes: ", db.bgp.count())
print("Total Peers: ", len(peer_asns))
print("Next Hop IP Address: ", len(next_hop_ips))
print("Origin ASNs: ", len(origin_asns))
#print("ISP:", isp)

#print(find_network(ip, subnet_mask))
# print("Google: ")
for prefix in isp:
    #print(prefix)
    print(asn_name_query(prefix['origin_as']))

# for ip in next_hop_ips:
#     print(reverse_dns_query(ip))
# for peer in peer_asns:
#     print(str(peer) + ' - ' + asn_name_query(peer) + ": ", db.bgp.count({"next_hop_asn": peer}))
