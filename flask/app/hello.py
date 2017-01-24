from flask import Flask, jsonify, render_template
from pymongo import MongoClient
import dns.resolver
import ipaddress
import time
from itertools import islice
from collections import Counter
import threading
from apscheduler.schedulers.background import BackgroundScheduler

_DEFAULT_ASN = 3701
_CUSTOMER_BGP_COMMUNITY = '3701:370'
_BGP_COMMUNITY_MAP = {
      '3701:111': 'Level3-Prepend-1',
      '3701:112': 'Level3-Prepend-2',
      '3701:113': 'Level3-SEAT-Depref',
      '3701:114': 'Level3-WSAC-Depref',
      '3701:121': 'Level3-WSAC-Prepend-1',
      '3701:122': 'Level3-WSAC-Prepend-2',
      '3701:370': 'Customers',
      '3701:371': 'Customers-NO-I2-RE',
      '3701:372': 'Customers-NO-I2-CP',
      '3701:380': 'Transit',
      '3701:381': 'Level3-SEAT',
      '3701:382': 'Level3-WSAC',
      '3701:390': 'OIX',
      '3701:391': 'I2-RE',
      '3701:392': 'NWAX',
      '3701:393': 'PNWGP',
      '3701:394': 'I2-CPS',
      '3701:395': 'SeattleIX',
      '3701:500': 'PT-ODE-USERS',
      '3701:501': 'PT-ODE-PROVIDERS',
      '3701:666': 'BH-LOCAL',
      '64496:0': 'Cymru-UTRS',
      '65333:888': 'Cymru-BOGONs',
      '65535:65281': 'No-Export',
}

app = Flask(__name__)


def db_connect():
    """Return a connection to the Mongo Database."""
    client = MongoClient(host='mongo')
    return(client.bgp)


def take(n, iterable):
    """Return first n items of the iterable as a list."""
    return list(islice(iterable, n))


def find_network(ip, netmask):
    """Given an IPv4 or IPv6 address, recursively search for and return the most
       specific prefix in the MongoDB collection.
    """
    try:
        db = db_connect()
        network = str(ipaddress.ip_network(ipaddress.ip_address(ip)).supernet(new_prefix=netmask))
        result = db.bgp.find_one({'prefix': network})
        if result is not None:
            return(result)
        elif netmask == 0:
            return(None)
        else:
            return(find_network(ip, netmask-1))
    except:
        return(None)


def asn_name_query(asn):
    """Given an *asn*, return the name."""
    if asn is None:
        asn = _DEFAULT_ASN
    if 64496 <= asn <= 64511:
        return('RFC5398 - Private Use ASN')
    if 64512 <= asn <= 65535 or 4200000000 <= asn <= 4294967295:
        return('RFC6996 - Private Use ASN')
    try:
        query = 'as{number}.asn.cymru.com'.format(number=str(asn))
        resolver = dns.resolver.Resolver()
        answers = resolver.query(query, 'TXT')
        for rdata in answers:
            return(str(rdata).split('|')[-1].split(',', 2)[0].strip())
    except:
        return('(DNS Error)')


def is_peer(asn):
    """Is *asn* in the list of directy connected ASNs."""
    db = db_connect()
    if asn in db.bgp.distinct('next_hop_asn'):
        return True
    else:
        return False


def reverse_dns_query(ip):
    """Given an *ip*, return the reverse dns."""
    try:
        addr = dns.reversename.from_address(str(ip))
        resolver = dns.resolver.Resolver()
        return str(resolver.query(addr, 'PTR')[0])[:-1]
    except:
        return('(DNS Error)')


def peer_count():
    """Return the number of directly connected ASNs."""
    db = db_connect()
    return(len(db.bgp.distinct('next_hop_asn')))


def prefix_count(version):
    """Given the IP version, return the number of prefixes in the database."""
    db = db_connect()
    return(db.bgp.find({'ip_version': version}).count())


def nexthop_ip_count():
    """Return the number of unique next hop IPv4 and IPv6 addresses."""
    db = db_connect()
    return(len(db.bgp.distinct('nexthop')))


def epoch_to_date(epoch):
    """Given an *epoch* time stamp, return a human readable equivalent."""
    return(time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime(epoch)))


def avg_as_path_length(decimal_point_accuracy=3):
    """Return the computed average *as_path* length of all prefixes in the
    database.  Using a python *set* to remove any AS prepending."""
    db = db_connect()
    as_path_counter = 0
    all_prefixes = db.bgp.find()
    for prefix in all_prefixes:
        try:
            as_path_counter += len(set(prefix['as_path']))  # sets remove duplicate ASN prepending
        except:
            pass
    return(round(as_path_counter/(all_prefixes.count() * 1.0), decimal_point_accuracy))


def top_peers(count):
    """Return a sorted list of top peer dictionaries ordered by prefix count.
    Limit to *count*."""
    db = db_connect()
    peers = {peer: db.bgp.find({'next_hop_asn': peer}).count()
             for peer in db.bgp.distinct('next_hop_asn')}
    return([{'asn': asn[0],
             'count': asn[1],
             'name': asn_name_query(asn[0])}
            for asn in take(count, sorted(peers.items(), key=lambda x: x[1], reverse=True))])


def get_list_of(customers=False, peers=False, community=_CUSTOMER_BGP_COMMUNITY):
    """Return a list of prefix dictionaries.  Specify which type of prefix to
    return by setting *customers* or *peers* to True."""
    db = db_connect()
    if peers:
        query_results = {prefix['next_hop_asn'] for prefix in db.bgp.find()}
    else:
        query_results = {prefix['next_hop_asn'] for prefix in db.bgp.find({'communities': community})}
    return([{'asn': asn if asn is not None else _DEFAULT_ASN,  # Set "None" ASNs to default
             'name': asn_name_query(asn),
             'ipv4_count': db.bgp.find({'next_hop_asn': asn, 'ip_version': 4}).count(),
             'ipv6_count': db.bgp.find({'next_hop_asn': asn, 'ip_version': 6}).count()}
            for asn in query_results])


def cidr_breakdown():
    """ Return a list of IPv4 and IPv6 network mask counters."""
    db = db_connect()
    ipv4_masks = [int(prefix['prefix'].split('/', 1)[1])
                  for prefix in db.bgp.find({'ip_version': 4})]
    ipv6_masks = [int(prefix['prefix'].split('/', 1)[1])
                  for prefix in db.bgp.find({'ip_version': 6})]
    # Use a *Counter* to count masks in the lists, then combine, sort on mask, and return results
    return(sorted(
           [{'mask': mask,
             'count': count,
             'ip_version': 4}
            for mask, count in list(Counter(ipv4_masks).items())]
           +
           [{'mask': mask,
             'count': count,
             'ip_version': 6}
            for mask, count in list(Counter(ipv6_masks).items())], key=lambda x: x['mask']))


def communities_count():
    """Return a list of BGP communities and their count"""
    db = db_connect()
    return([{'community': community,
             'count': db.bgp.find({'communities': {'$regex': community}}).count(),
             'name': _BGP_COMMUNITY_MAP.get(community)}
            for community in db.bgp.distinct('communities')])


@app.route('/hello/', methods=['GET'])
def hello_index():
    data = myStats.get_data()
    top_peers = data['top_n_peers']
    cidr_breakdown = data['cidr_breakdown']
    communities = data['communities']
    peers = data['peers']
    return render_template('hello.html', **locals())


@app.route('/search/<query>', methods=['GET'])
def search_index(query):
    db = db_connect()
    number = 0
    prefixes = []
    for t in query.split():
        try:
            number = int(t)
        except:
            pass
    try:
        query = query.lower()
    except:
        pass
    network = find_network(query, netmask=32)
    if network is None:
        result = db.bgp.find({'$or': [{'next_hop_asn': int(number)},
                                      {'prefix': {'$regex': str(query)}}]})
        for network in result:
            prefixes.append({'origin_as': network['origin_as'],
                             'nexthop': network['nexthop'],
                             'as_path': network['as_path'],
                             'prefix': network['prefix'],
                             'next_hop_asn': network['next_hop_asn'],
                             'updated': epoch_to_date(network['timestamp']),
                             'name': asn_name_query(network['origin_as']),
                             'med': network['med'],
                             'local_pref': network['local_pref'],
                             'communities': network['communities']})
        return jsonify({'prefixes': prefixes})
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


@app.route('/bgp/api/v1.0/ip/<ip>', methods=['GET'])
def get_ip(ip):
    if ipaddress.ip_address(ip).version == 4:
        network = find_network(ip, netmask=32)
    elif ipaddress.ip_address(ip).version == 6:
        network = find_network(ip, netmask=128)
    else:
        network = None
    if network is None:
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

    if asn == _DEFAULT_ASN:
        routes = db.bgp.find({'origin_as': None})
    else:
        routes = db.bgp.find({'origin_as': asn})

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

    peer_asns = db.bgp.distinct('next_hop_asn')

    for asn in peer_asns:
        next_hop_ips = db.bgp.find({'next_hop_asn': asn}).distinct('nexthop')
        if asn is None:
            asn = _DEFAULT_ASN
        isp_origin_as = db.bgp.find({'origin_as': asn})
        isp_nexthop_as = db.bgp.find({'next_hop_asn': asn})
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


@app.route('/bgp/api/v1.0/stats', methods=['GET'])
def get_stats():
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
        self.peer_counter = 0
        self.ipv4_table_size = 0
        self.ipv6_table_size = 0
        self.nexthop_ip_counter = 0
        self.avg_as_path_length = 0
        self.top_n_peers = []
        self.cidr_breakdown = []
        self.communities = []
        self.peers = []
        self.customers = []
        self.customer_count = 0
        self.customer_ipv4_prefixes = 0
        self.customer_ipv6_prefixes = 0
        self.timestamp = epoch_to_date(time.time())

    def get_json(self):
        return jsonify({'peer_count': self.peer_counter,
                        'ipv4_table_size': self.ipv4_table_size,
                        'ipv6_table_size': self.ipv6_table_size,
                        'nexthop_ip_count': self.nexthop_ip_counter,
                        'avg_as_path_length': self.avg_as_path_length,
                        'top_n_peers': self.top_n_peers,
                        'cidr_breakdown': self.cidr_breakdown,
                        'communities': self.communities,
                        'peers': self.peers,
                        'customers': self.customers,
                        'customer_count': self.customer_count,
                        'customer_ipv4_prefixes': self.customer_ipv4_prefixes,
                        'customer_ipv6_prefixes': self.customer_ipv6_prefixes,
                        'timestamp': self.timestamp})

    def get_data(self):
        return ({'peer_count': self.peer_counter,
                 'ipv6_table_size': self.ipv6_table_size,
                 'ipv4_table_size': self.ipv4_table_size,
                 'nexthop_ip_count': self.nexthop_ip_counter,
                 'avg_as_path_length': self.avg_as_path_length,
                 'top_n_peers': self.top_n_peers,
                 'cidr_breakdown': self.cidr_breakdown,
                 'communities': self.communities,
                 'peers': self.peers,
                 'customers': self.customers,
                 'customer_count': self.customer_count,
                 'customer_ipv4_prefixes': self.customer_ipv4_prefixes,
                 'customer_ipv6_prefixes': self.customer_ipv6_prefixes,
                 'timestamp': self.timestamp})

    def update_stats(self):
        self.peer_counter = peer_count()
        self.ipv4_table_size = prefix_count(4)
        self.ipv6_table_size = prefix_count(6)
        self.nexthop_ip_counter = nexthop_ip_count()
        self.timestamp = epoch_to_date(time.time())
        customers = get_list_of(customers=True)
        self.customer_count = len(customers)
        self.customer_ipv4_prefixes = 0
        self.customer_ipv6_prefixes = 0
        for customer in customers:
            self.customer_ipv4_prefixes += customer['ipv4_count']
            self.customer_ipv6_prefixes += customer['ipv6_count']

    def update_advanced_stats(self):
        self.avg_as_path_length = avg_as_path_length()
        self.top_n_peers = top_peers(5)
        self.cidr_breakdown = cidr_breakdown()
        self.peers = get_list_of(peers=True)
        self.customers = get_list_of(customers=True)
        self.communities = communities_count()
        self.timestamp = epoch_to_date(time.time())


sched = BackgroundScheduler()
myStats = Stats()
threading.Thread(target=myStats.update_stats).start()
threading.Thread(target=myStats.update_advanced_stats).start()
sched.add_job(myStats.update_stats, 'interval', seconds=5)
sched.add_job(myStats.update_advanced_stats, 'interval', seconds=90)
sched.start()

if __name__ == '__main__':
    app.run(debug=True)
