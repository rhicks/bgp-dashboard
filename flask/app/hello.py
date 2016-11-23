#!/usr/bin/env python3
from flask import Flask, jsonify, url_for, request
import json
import pymongo
from pymongo import MongoClient
import dns.resolver

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

@app.route('/todo/api/v1.0/tasks', methods=['GET'])
def get_tasks():
    return jsonify({'tasks': tasks})

@app.route('/bgp/api/v1.0/peer/<int:asn>', methods=['GET'])
def get_prefixes(asn):
    client = MongoClient(host='mongo')
    db = client.bgp
    prefixes = []
    
    # peer_asns = db.bgp.distinct("next_hop_asn")
    # next_hop_ips = db.bgp.distinct("nexthop")
    # origin_asns =  db.bgp.distinct("origin_as")
    google = db.bgp.find({"next_hop_asn": asn})
    
    for prefix in google:
        prefixes.append({'prefix': prefix['prefix'],
                         'origin_as': prefix['origin_as'],
                         'nexthop_ip': prefix['nexthop'],
                         'next_hop_asn': prefix['next_hop_asn'],
                         'as_path': prefix['as_path']})
    
    return jsonify({'prefix_list': prefixes})
    

@app.route('/bgp/api/v1.0/peers', methods=['GET'])
def get_peers():
    client = MongoClient(host='mongo')
    db = client.bgp
    peers = []
    
    peer_asns = db.bgp.distinct("next_hop_asn")
    #next_hop_ips = db.bgp.distinct("nexthop")
    #origin_asns =  db.bgp.distinct("origin_as")
    #google = db.bgp.find({"next_hop_asn": asn})
    
    for asn in peer_asns:
        next_hop_ips = db.bgp.find({"next_hop_asn": asn}).distinct("nexthop")
        if asn == None:
            asn = 3701
        url = request.url_root + 'bgp/api/v1.0/peer/' + str(asn) 
        peers.append({'asn': asn, 'next_hop_ips': next_hop_ips, 'url': url})
    
    return jsonify({'peers': peers})
    
    # with open('test-log.json', 'r') as f:
    #      data = json.load(f)
    # 
    # prefixes = []
    # 
    # for k, v in data.items():
    #     prefix = None
    #     nexthop = None
    #     as_path = None
    #     next_hop_asn = None
    #     origin_as = None
    #     prefix = v[0]['nlri']['prefix']
    #     for attribute in v[0]['attrs']:
    #         if attribute['type'] == 3:
    #             nexthop = attribute['nexthop']
    #         elif attribute['type'] == 2:
    #             try:
    #                 as_path = attribute['as_paths'][0]['asns']
    #                 next_hop_asn = attribute['as_paths'][0]['asns'][0]
    #                 origin_as = attribute['as_paths'][0]['asns'][-1]
    #             except:
    #                 pass
    #     prefixes.append({'prefix': prefix, 'nexthop': nexthop, 'as_path': as_path, 'next_hop_asn': next_hop_asn, 'origin_as': origin_as})
    # 
    # return jsonify({'peers': prefixes})

if __name__ == '__main__':
    app.run(debug=True)
