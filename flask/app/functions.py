from pymongo import MongoClient
import dns.resolver
import ipaddress
import time
from itertools import islice
from collections import Counter
import constants as C
from flask import jsonify, request


def db_connect():
    """Return a connection to the Mongo Database."""
    client = MongoClient(host='mongodb')
    return(client.bgp)


def take(n, iterable):
    """Return first n items of the iterable as a list."""
    return list(islice(iterable, n))


def find_network(ip, netmask):
    """Given an IPv4 or IPv6 address, recursively search for and return the most
       specific prefix in the MongoDB collection that is active.
    """
    try:
        db = db_connect()
        network = str(ipaddress.ip_network(ipaddress.ip_address(ip)).supernet(new_prefix=netmask))
        result = db.bgp.find_one({'_id': network, 'active': True})
        if result is not None:
            return(result)
        elif netmask == 0:
            return(None)
        else:
            return(find_network(ip, netmask-1))
    except Exception:
        return(None)


def asn_name_query(asn):
    """Given an *asn*, return the name."""
    if asn is None:
        asn = C.DEFAULT_ASN
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
    except Exception:
        return('(DNS Error)')


def is_peer(asn):
    """Is *asn* in the list of directy connected ASNs."""
    db = db_connect()
    if asn in db.bgp.distinct('nexthop_asn'):
        return True
    else:
        return False


def is_transit(prefix, transit_bgp_community=C.TRANSIT_BGP_COMMUNITY):
    """Is the *prefix* counted as transit?"""
    if C.TRANSIT_BGP_COMMUNITY in prefix['communities']:
        return True
    else:
        return False


def reverse_dns_query(ip):
    """Given an *ip*, return the reverse dns."""
    try:
        addr = dns.reversename.from_address(str(ip))
        resolver = dns.resolver.Resolver()
        return str(resolver.query(addr, 'PTR')[0])[:-1]
    except Exception:
        return('(DNS Error)')


def dns_query(name):
    """Given a *name*, return the ip dns."""
    try:
        # addr = dns.reversename.from_address(str(ip))
        resolver = dns.resolver.Resolver()
        return str(resolver.query(str(name), 'A')[0])
    except Exception:
        return('(DNS Error)')


def peer_count():
    """Return the number of directly connected ASNs."""
    db = db_connect()
    return(len(db.bgp.distinct('nexthop_asn', {'active': True})))


def prefix_count(version):
    """Given the IP version, return the number of prefixes in the database."""
    db = db_connect()
    return(db.bgp.find({'ip_version': version, 'active': True}).count())


def nexthop_ip_count():
    """Return the number of unique next hop IPv4 and IPv6 addresses."""
    db = db_connect()
    return(len(db.bgp.distinct('nexthop', {'active': True})))


def epoch_to_date(epoch):
    """Given an *epoch* time stamp, return a human readable equivalent."""
    return(time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime(epoch)))


def avg_as_path_length(decimal_point_accuracy=2):
    """Return the computed average *as_path* length of all prefixes in the
    database.  Using a python *set* to remove any AS prepending."""
    db = db_connect()
    as_path_counter = 0
    all_prefixes = db.bgp.find({'active': True})
    for prefix in all_prefixes:
        try:
            as_path_counter += len(set(prefix['as_path']))  # sets remove duplicate ASN prepending
        except Exception:
            pass
    return(round(as_path_counter/(all_prefixes.count() * 1.0), decimal_point_accuracy))


def top_peers(count):
    """Return a sorted list of top peer dictionaries ordered by prefix count.
    Limit to *count*."""
    db = db_connect()
    peers = {peer: db.bgp.find({'nexthop_asn': peer, 'active': True}).count()
             for peer in db.bgp.distinct('nexthop_asn')}
    return([{'asn': asn[0],
             'count': asn[1],
             'name': asn_name_query(asn[0])}
            for asn in take(count, sorted(peers.items(), key=lambda x: x[1], reverse=True))])


def get_list_of(customers=False, peers=False, community=C.CUSTOMER_BGP_COMMUNITY):
    """Return a list of prefix dictionaries.  Specify which type of prefix to
    return by setting *customers* or *peers* to True."""
    db = db_connect()
    if peers:
        query_results = {prefix['nexthop_asn'] for prefix in db.bgp.find({'active': True})}
    if customers:
        query_results = {prefix['nexthop_asn'] for prefix in db.bgp.find({'communities': community, 'active': True})}
    return([{'asn': asn if asn is not None else C.DEFAULT_ASN,  # Set "None" ASNs to default
             'name': asn_name_query(asn),
             'ipv4_origin_count': db.bgp.find({'origin_asn': asn, 'ip_version': 4, 'active': True}).count(),
             'ipv6_origin_count': db.bgp.find({'origin_asn': asn, 'ip_version': 6, 'active': True}).count(),
             'ipv4_nexthop_count': db.bgp.find({'nexthop_asn': asn, 'ip_version': 4, 'active': True}).count(),
             'ipv6_nexthop_count': db.bgp.find({'nexthop_asn': asn, 'ip_version': 6, 'active': True}).count(),
             'asn_count':  len(db.bgp.distinct('as_path.1', {'nexthop_asn': asn, 'active': True}))}
            for asn in query_results])


def cidr_breakdown():
    """ Return a list of IPv4 and IPv6 network mask counters."""
    db = db_connect()
    ipv4_masks = [int(prefix['_id'].split('/', 1)[1])
                  for prefix in db.bgp.find({'ip_version': 4, 'active': True})]
    ipv6_masks = [int(prefix['_id'].split('/', 1)[1])
                  for prefix in db.bgp.find({'ip_version': 6, 'active': True})]
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
             'count': db.bgp.find({'communities': {'$regex': str(community)}, 'active': True}).count(),
             'name': None if C.BGP_COMMUNITY_MAP.get(community) is None else C.BGP_COMMUNITY_MAP.get(community)}
            for community in db.bgp.distinct('communities') if community is not None])


def get_ip_json(ip, include_history=True):
    if '/' in ip:
        ip = ip.lstrip().rstrip().split('/')[0]
    try:
        if ipaddress.ip_address(ip).version == 4:
            network = find_network(ip, netmask=32)
        elif ipaddress.ip_address(ip).version == 6:
            network = find_network(ip, netmask=128)
    except Exception:
        try:
            ipadr = dns_query(ip).strip()
            if ipaddress.ip_address(ipadr).version == 4:
                network = find_network(ipadr, netmask=32)
            elif ipaddress.ip_address(ipadr).version == 6:
                network = find_network(ipadr, netmask=128)
        except Exception as e:
            return(jsonify(str(e)))
    if network:
        if include_history:
            history = network['history']
        else:
            history = request.base_url + '/history'
        return {'prefix': network['_id'],
                'ip_version': network['ip_version'],
                'is_transit': is_transit(network),
                'origin_asn': network['origin_asn'],
                'name': asn_name_query(network['origin_asn']),
                'nexthop': network['nexthop'],
                'nexthop_asn': network['nexthop_asn'],
                'as_path': network['as_path'],
                'med': network['med'],
                'local_pref': network['local_pref'],
                'communities': network['communities'],
                'route_origin': network['route_origin'],
                'atomic_aggregate': network['atomic_aggregate'],
                'aggregator_as': network['aggregator_as'],
                'aggregator_address': network['aggregator_address'],
                'originator_id': network['originator_id'],
                'cluster_list': network['cluster_list'],
                'age': network['age'],
                'history': history}
    else:
        return {}
