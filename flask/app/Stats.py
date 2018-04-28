import time
from flask import jsonify
from functions import epoch_to_date, peer_count, prefix_count
from functions import nexthop_ip_count, get_list_of, avg_as_path_length
from functions import top_peers, cidr_breakdown, communities_count


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
            self.customer_ipv4_prefixes += customer['ipv4_origin_count']
            self.customer_ipv6_prefixes += customer['ipv6_origin_count']

    def update_advanced_stats(self):
        self.avg_as_path_length = avg_as_path_length()
        self.top_n_peers = top_peers(5)
        self.cidr_breakdown = cidr_breakdown()
        self.peers = get_list_of(peers=True)
        self.customers = get_list_of(customers=True)
        self.communities = communities_count()
        self.timestamp = epoch_to_date(time.time())
