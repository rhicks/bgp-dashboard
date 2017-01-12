from flask import Flask, jsonify, url_for, request, render_template
import json
import requests
import pymongo
from pymongo import MongoClient
import dns.resolver
import ipaddress
import time
from itertools import islice
from collections import Counter
import threading
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

def db_connect():
    client = MongoClient(host='mongo')
    return(client.bgp)

def take(n, iterable):
    "Return first n items of the iterable as a list"
    return list(islice(iterable, n))

def find_network(ip, netmask):
    try:
        if ipaddress.ip_address(ip).version == 4:
            db = db_connect()
            network = str(ipaddress.ip_network(ipaddress.ip_address(ip)).supernet(new_prefix=netmask))
            result = db.bgp.find_one({"prefix": network})
            if result != None:
                return(result)
            elif netmask == 0:
                return(None)
            else:
                return(find_network(ip, netmask-1))
        elif ipaddress.ip_address(ip).version == 6:
            db = db_connect()
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
    db = db_connect()
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
    db = db_connect()
    peer_asns = db.bgp.distinct("next_hop_asn")
    return(len(peer_asns))

def prefix_count(version):
    db = db_connect()
    result = db.bgp.find({"ip_version": version})
    return(result.count())

def nexthop_ip_count():
    db = db_connect()
    nexthop_ip_count = db.bgp.distinct("nexthop")
    return(len(nexthop_ip_count))

def epoch_to_date(epoch):
    return(time.strftime("%Y-%m-%d %H:%M:%S %Z", time.gmtime(epoch)))

def avg_as_path_length():
    db = db_connect()
    as_path_counter = 0

    all = db.bgp.find()
    for prefix in all:
        try:
            as_path_counter += len(set(prefix['as_path']))
        except:
            pass
    path_length = round(as_path_counter/(all.count() * 1.0), 4)
    return(path_length)

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
    return(json_data)

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

    return(json_data)

def communities_count():
    db = db_connect()
    communities = db.bgp.distinct("communities")
    json_data = []

    for comm in communities:
        json_data.append({
            'community': comm,
            'count': db.bgp.find({'communities': {'$regex' : comm}}).count()})

    return(json_data)

@app.route('/', methods=['GET'])
def index():
    # num_peers = peer_count()
    return render_template('home.html', **locals())

@app.route('/hello/', methods=['GET'])
def hello_index():
    return render_template('hello.html', **locals())

@app.route('/bgp/api/v1.0/ip/<ip>', methods=['GET'])
def get_ip(ip):
    db = db_connect()
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
                        'name': asn_name_query(network['origin_as']),
                        'med': network['med'],
                        'local_pref': network['local_pref'],
                        'communities': network['communities']})

@app.route('/bgp/api/v1.0/asn/<int:asn>', methods=['GET'])
def get_asn_prefixes(asn):
    db = db_connect()
    prefixes = []

    routes = db.bgp.find({"origin_as": asn})

    for prefix in routes:
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
                    'origin_prefix_count': routes.count(),
                    'is_peer': is_peer(asn),
                    'origin_prefix_list': prefixes})

@app.route('/bgp/api/v1.0/peers', methods=['GET'])
def get_peers():
    db = db_connect()
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
    db = db_connect()
    peers = []

    return jsonify({'peer_count': peer_count()})

@app.route('/bgp/api/v1.0/stats', methods=['GET'])
def get_stats():
    return myStats.get_json()

@app.route('/bgp/api/v1.0/stats/advanced', methods=['GET'])
def advanced_stats():
    return myStats.get_json()

@app.route('/bgp/api/v1.0/asn/<int:asn>/transit', methods=['GET'])
def get_transit_prefixes(asn):
    db = db_connect()
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

class Stats(object):
    def __init__(self):
        self.peer_counter       = 0
        self.ipv4_table_size    = 0
        self.ipv6_table_size    = 0
        self.nexthop_ip_counter = 0
        self.avg_as_path_length = 0
        self.top_n_peers        = None
        self.cidr_breakdown     = None
        self.communities        = None
        self.timestamp          = epoch_to_date(time.time())

    def get_json(self):
        return jsonify({'peer_count':         self.peer_counter,
                        'ipv4_table_size':    self.ipv4_table_size,
                        'ipv6_table_size':    self.ipv6_table_size,
                        'nexthop_ip_count':   self.nexthop_ip_counter,
                        'avg_as_path_length': self.avg_as_path_length,
                        'top_n_peers':        self.top_n_peers,
                        'cidr_breakdown':     self.cidr_breakdown,
                        'communities':        self.communities,
                        'timestamp':          self.timestamp})

    def update_stats(self):
        self.peer_counter = peer_count()
        self.ipv4_table_size = prefix_count(4)
        self.ipv6_table_size = prefix_count(6)
        self.nexthop_ip_counter = nexthop_ip_count()
        self.timestamp = epoch_to_date(time.time())

    def update_advanced_stats(self):
        self.avg_as_path_length = avg_as_path_length()
        self.top_n_peers = top_peers(10)
        self.cidr_breakdown = cidr_breakdown()
        self.communities = communities_count()
        self.timestamp = epoch_to_date(time.time())

sched = BackgroundScheduler()
myStats = Stats()
sched.add_job(myStats.update_stats, 'interval', seconds=5)
sched.add_job(myStats.update_advanced_stats, 'interval', seconds=30)
sched.start()

if __name__ == '__main__':
    app.run(debug=True)
