#!/usr/bin/env python3
from flask import Flask, jsonify, url_for, request, render_template
import json
import requests
import pymongo
from pymongo import MongoClient
import dns.resolver
import ipaddress
import time

app = Flask(__name__)

tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol', 
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web', 
        'done': False
    },
    {
        'id': 3,
        'title': u'Learn Flask',
        'description': u'Need to find a good Flask tutorial on the web', 
        'done': False
    },
    {
        'id': 4,
        'title': u'Learn BGP',
        'description': u'Need to find a good BGP tutorial on the web', 
        'done': False
    },
    {
        'id': 5,
        'title': u'Learn Mongo',
        'description': u'Need to find a good Mongo tutorial on the web', 
        'done': False
    }
]

def find_network(ip, netmask):
    try:
        if ipaddress.ip_address(ip).version == 4:
            client = MongoClient(host='mongo')
            db = client.bgp
            network = str(ipaddress.ip_network(ipaddress.ip_address(ip)).supernet(new_prefix=netmask))
            result = db.bgp.find_one({"prefix": network})
            if result != None:
                return(result)
            elif netmask == 0:
                return(None)
            else:
                return(find_network(ip, netmask-1))
        elif ipaddress.ip_address(ip).version == 6:
            client = MongoClient(host='mongo')
            db = client.bgp
            network = str(ipaddress.ip_network(ipaddress.ip_address(ip)).supernet(new_prefix=netmask + 32))
            result = db.bgp.find_one({"prefix": network})
            if result != None:
                return(result)
            elif netmask == 0:
                return(None)
            else:
                return(find_network(ip, netmask-1))
        else:
            return(None)
    except:
        return(None)
        
        
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

def is_peer(asn):
    client = MongoClient(host='mongo')
    db = client.bgp
    peers = db.bgp.distinct("next_hop_asn")
    if asn in peers:
        return True
    else:
        return False
        
def reverse_dns_query(ip):
    try:
        addr = dns.reversename.from_address(str(ip))
        resolver = dns.resolver.Resolver()
        return str(resolver.query(addr,"PTR")[0])[:-1]
    except:
        return("(DNS Error)")

def peer_count():
    client = MongoClient(host='mongo')
    db = client.bgp
    peer_asns = db.bgp.distinct("next_hop_asn")
    return(len(peer_asns))
    
def nexthop_ip_count():
    client = MongoClient(host='mongo')
    db = client.bgp
    nexthop_ip_count = db.bgp.distinct("nexthop")
    return(len(nexthop_ip_count))
    
def epoch_to_date(epoch):
    return(time.strftime("%Y-%m-%d %H:%M:%S %Z", time.gmtime(epoch)))
    
def prefix_count(version):
    client = MongoClient(host='mongo')
    db = client.bgp
    result = db.bgp.find({"ip_version": version})
    return(result.count())

@app.route('/', methods=['GET'])
def index():
    # num_peers = peer_count()
    return render_template('home.html', **locals())

@app.route('/hello/', methods=['GET'])
def hello_index():
    # number_of_peers = peer_count()
    # number_of_ipv4_prefixes = prefix_count(version=4)
    # number_of_ipv6_prefixes = prefix_count(version=6)
    return render_template('hello.html', **locals())
    
@app.route('/todo/api/v1.0/tasks', methods=['GET'])
def get_tasks():
    return jsonify({'tasks': tasks})
    
@app.route('/bgp/api/v1.0/ip/<ip>', methods=['GET'])
def get_ip(ip):
    client = MongoClient(host='mongo')
    db = client.bgp
    network = find_network(ip, netmask=32)
    if network == None:
        return jsonify({})
    else:
        return jsonify({'origin_as': network['origin_as'],
                        'nexthop': network['nexthop'],
                        'as_path': network['as_path'],
                        'prefix': network['prefix'],
                        'next_hop_asn': network['next_hop_asn'],
                        'updated': epoch_to_date(network['timestamp']),
                        'name': asn_name_query(network['origin_as'])})

@app.route('/bgp/api/v1.0/peer/<int:asn>', methods=['GET'])
def get_prefixes(asn):
    client = MongoClient(host='mongo')
    db = client.bgp
    prefixes = []

    google = db.bgp.find({"next_hop_asn": asn})
    
    for prefix in google:
        prefixes.append({'prefix': prefix['prefix'],
                         'origin_as': prefix['origin_as'],
                         'nexthop_ip': prefix['nexthop'],
                         'next_hop_asn': prefix['next_hop_asn'],
                         'as_path': prefix['as_path'],
                         'updated': epoch_to_date(prefix['timestamp']),
                         'name': asn_name_query(asn)})
    
    return jsonify({'prefix_list': prefixes})
    
@app.route('/bgp/api/v1.0/asn/<int:asn>', methods=['GET'])
def get_asn_prefixes(asn):
    client = MongoClient(host='mongo')
    db = client.bgp
    prefixes = []
    
    google = db.bgp.find({"origin_as": asn})
    
    for prefix in google:
        prefixes.append({'prefix': prefix['prefix'],
                         'origin_as': prefix['origin_as'],
                         'nexthop_ip': prefix['nexthop'],
                         'nexthop_ip_dns': reverse_dns_query(prefix['nexthop']),
                         'nexthop_asn': prefix['next_hop_asn'],
                         'as_path': prefix['as_path'],
                         'updated': epoch_to_date(prefix['timestamp']),
                         'name': asn_name_query(asn)})
    
    return jsonify({'asn': asn,
                    'name': asn_name_query(asn),
                    'origin_prefix_count': google.count(),
                    'is_peer': is_peer(asn),
                    'origin_prefix_list': prefixes})

@app.route('/bgp/api/v1.0/peers', methods=['GET'])
def get_peers():
    client = MongoClient(host='mongo')
    db = client.bgp
    peers = []
    
    peer_asns = db.bgp.distinct("next_hop_asn")
    
    for asn in peer_asns:
        next_hop_ips = db.bgp.find({"next_hop_asn": asn}).distinct("nexthop")
        if asn == None:
            asn = 3701
        url = request.url_root + 'bgp/api/v1.0/peer/' + str(asn) 
        isp_origin_as = db.bgp.find({"origin_as": asn})
        isp_nexthop_as = db.bgp.find({"next_hop_asn": asn})
        if isp_nexthop_as.count() > isp_origin_as.count():
            transit_provider = True
        else:
            transit_provider = False
        peers.append({'asn': asn,
                      'name': asn_name_query(asn),
                      'next_hop_ips': next_hop_ips,
                      'origin_prefix_count': isp_origin_as.count(),
                      'nexthop_prefix_count': isp_nexthop_as.count(),
                      'transit_provider': transit_provider})
    
    return jsonify({'peers': peers})
    
@app.route('/bgp/api/v1.0/peers/count', methods=['GET'])
def get_peer_count():
    client = MongoClient(host='mongo')
    db = client.bgp
    peers = []
    
    return jsonify({'peer_count': peer_count()})
    
@app.route('/bgp/api/v1.0/stats', methods=['GET'])
def get_stats():
    return jsonify({'peer_count': peer_count(),
                    'ipv4_table_size': prefix_count(4),
                    'ipv6_table_size': prefix_count(6),
                    'nexthop_ip_count': nexthop_ip_count()})

@app.route('/bgp/api/v1.0/asn/<int:asn>/transit', methods=['GET'])
def get_transit_prefixes(asn):
    client = MongoClient(host='mongo')
    db = client.bgp
    all_asns = db.bgp.find({})
    prefixes = []

    for prefix in all_asns:
        if prefix['as_path']:
            if asn in prefix['as_path']:
                prefixes.append(prefix['prefix'])
            else:
                pass
        else:
            pass
    
    return jsonify({'asn': asn,
                    'name': asn_name_query(asn),
                    'transit_prefix_count': len(prefixes),
                    'transit_prefix_list': prefixes})

if __name__ == '__main__':
    app.run(debug=True)
