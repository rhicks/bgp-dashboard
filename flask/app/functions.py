import ipaddress
import dns.resolver
import constants as C
from flask import jsonify, request
from pymongo import MongoClient


def db_connect():
    """Return a connection to the Mongo Database."""
    client = MongoClient(host='mongodb')
    return(client.bgp)


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


def dns_query(name, type='A'):
    """Given a *name*, return the ip dns."""
    try:
        # addr = dns.reversename.from_address(str(ip))
        resolver = dns.resolver.Resolver()
        answers = resolver.query(str(name), type)
        if type is 'A':
            return str(answers[0])
        elif type is 'NS':
            domains = []
            for record in answers:
              domains.append(str(record.target))
            return domains
        elif type is 'SOA':
            return str(answers[0]).split()[0]
    except Exception:
        return('(DNS Error)')


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
        return '(DNS Error)'

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
                'nexthop_ip_dns': reverse_dns_query(network['nexthop']),
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
                'originator_id_dns': reverse_dns_query(network['originator_id']),
                'cluster_list': network['cluster_list'],
                'age': network['age'],
                'history': history}
    else:
        return {}
