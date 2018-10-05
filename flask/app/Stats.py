import constants as C
import dns.resolver
import time
from collections import Counter
from flask import jsonify
from itertools import islice
from pymongo import MongoClient
from functions import asn_name_query


class Stats(object):
    def __init__(self):
        self.db = self.db_connect()
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
        self.timestamp = self.epoch_to_date(time.time())

    # @property
    # def peer_counter(self):
    #     return self._peer_counter

    # @peer_counter.setter
    # def peer_counter(self):
    #     self._peer_counter = len(self.db.bgp.distinct('nexthop_asn', {'active': True}))

    def db_connect(self):
        """Return a connection to the Mongo Database."""
        client = MongoClient(host='mongodb')
        return client.bgp

    def take(self, n, iterable):
        """Return first n items of the iterable as a list."""
        return list(islice(iterable, n))

    def peer_count(self):
        """Return the number of directly connected ASNs."""
        return len(self.db.bgp.distinct('nexthop_asn', {'active': True}))

    def prefix_count(self, version):
        """Given the IP version, return the number of prefixes in the database."""
        return self.db.bgp.find({'ip_version': version, 'active': True}).count()

    def nexthop_ip_count(self):
        """Return the number of unique next hop IPv4 and IPv6 addresses."""
        return len(self.db.bgp.distinct('nexthop', {'active': True}))

    def epoch_to_date(self, epoch):
        """Given an *epoch* time stamp, return a human readable equivalent."""
        return time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime(epoch))

    def get_list_of(self, customers=False, peers=False, community=C.CUSTOMER_BGP_COMMUNITY):
        """Return a list of prefix dictionaries.  Specify which type of prefix to
        return by setting *customers* or *peers* to True."""
        if peers:
            query_results = {prefix['nexthop_asn'] for prefix in self.db.bgp.find({'active': True})}
        if customers:
            query_results = {prefix['nexthop_asn'] for prefix in self.db.bgp.find({'communities': community, 'active': True})}
        return [{'asn': asn if asn is not None else C.DEFAULT_ASN,  # Set "None" ASNs to default
                 'name': asn_name_query(asn),
                 'ipv4_origin_count': self.db.bgp.find({'origin_asn': asn, 'ip_version': 4, 'active': True}).count(),
                 'ipv6_origin_count': self.db.bgp.find({'origin_asn': asn, 'ip_version': 6, 'active': True}).count(),
                 'ipv4_nexthop_count': self.db.bgp.find({'nexthop_asn': asn, 'ip_version': 4, 'active': True}).count(),
                 'ipv6_nexthop_count': self.db.bgp.find({'nexthop_asn': asn, 'ip_version': 6, 'active': True}).count(),
                 'asn_count':  len(self.db.bgp.distinct('as_path.1', {'nexthop_asn': asn, 'active': True}))}
                for asn in query_results]

    def avg_as_path_len(self, decimal_point_accuracy=2):
        """Return the computed average *as_path* length of all prefixes in the
        database.  Using a python *set* to remove any AS prepending."""
        as_path_counter = 0
        all_prefixes = self.db.bgp.find({'active': True})
        for prefix in all_prefixes:
            try:
                as_path_counter += len(set(prefix['as_path']))  # sets remove duplicate ASN prepending
            except Exception:
                pass
        return round(as_path_counter/(all_prefixes.count() * 1.0), decimal_point_accuracy)

    def communities_count(self):
        """Return a list of BGP communities and their count"""
        return [{'community': community,
                 'count': self.db.bgp.find({'communities': {'$regex': str(community)}, 'active': True}).count(),
                 'name': None if C.BGP_COMMUNITY_MAP.get(community) is None else C.BGP_COMMUNITY_MAP.get(community)}
                for community in self.db.bgp.distinct('communities') if community is not None]

    def cidrs(self):
        """ Return a list of IPv4 and IPv6 network mask counters."""
        ipv4_masks = [int(prefix['_id'].split('/', 1)[1])
                      for prefix in self.db.bgp.find({'ip_version': 4, 'active': True})]
        ipv6_masks = [int(prefix['_id'].split('/', 1)[1])
                      for prefix in self.db.bgp.find({'ip_version': 6, 'active': True})]
        # Use a *Counter* to count masks in the lists, then combine, sort on mask, and return results
        return sorted(
               [{'mask': mask,
                 'count': count,
                 'ip_version': 4}
                for mask, count in list(Counter(ipv4_masks).items())]
               +
               [{'mask': mask,
                 'count': count,
                 'ip_version': 6}
                for mask, count in list(Counter(ipv6_masks).items())], key=lambda x: x['mask'])

    def top_peers(self, count):
        """Return a sorted list of top peer dictionaries ordered by prefix count.
        Limit to *count*."""
        peers = {peer: self.db.bgp.find({'nexthop_asn': peer, 'active': True}).count()
                 for peer in self.db.bgp.distinct('nexthop_asn')}
        return [{'asn': asn[0],
                 'count': asn[1],
                 'name': asn_name_query(asn[0])}
                for asn in self.take(count, sorted(peers.items(), key=lambda x: x[1], reverse=True))]

    def get_data(self, json=False):
        data_dict = {
            'peer_count': self.peer_counter,
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
            'timestamp': self.timestamp}
        if json:
            return jsonify(data_dict)
        else:
            return data_dict

    def update_stats(self):
        self.peer_counter = self.peer_count()
        self.ipv4_table_size = self.prefix_count(4)
        self.ipv6_table_size = self.prefix_count(6)
        self.nexthop_ip_counter = self.nexthop_ip_count()
        self.timestamp = self.epoch_to_date(time.time())


    def update_advanced_stats(self):
        self.avg_as_path_length = self.avg_as_path_len()
        self.top_n_peers = self.top_peers(5)
        self.cidr_breakdown = self.cidrs()
        # self.customers = self.get_list_of(customers=True)
        self.communities = self.communities_count()
        self.customers = self.get_list_of(customers=True)
        self.peers = self.get_list_of(peers=True)
        self.customer_count = len(self.customers)
        self.customer_ipv4_prefixes = 0
        self.customer_ipv6_prefixes = 0
        for customer in self.customers:
            self.customer_ipv4_prefixes += customer['ipv4_origin_count']
            self.customer_ipv6_prefixes += customer['ipv6_origin_count']
        self.timestamp = self.epoch_to_date(time.time())
