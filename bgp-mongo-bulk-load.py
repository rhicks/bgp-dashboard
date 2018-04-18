#! /usr/bin/env python

from asn import ASN
from prefix import Prefix
import constants as C
import json
import sys
from pprint import pprint
import time


def build_json_update_entry(update_entry):
    """Given an update entry from GoBGP, return an update tuple"""
    prefix = origin = as_path = nexthop = med = local_pref = atomic_aggregate = None
    aggregator = communities = originator_id = cluster_list = withdrawal = age = None
    prefix = update_entry['nlri']['prefix']
    for attribute in update_entry['attrs']:
        if attribute['type'] == C.ORIGIN:
            origin = attribute['value']
        elif attribute['type'] == C.AS_PATH:
            try:
                as_path = attribute['as_paths'][0]['asns']
            except Exception:
                as_path = []
        elif attribute['type'] == C.NEXT_HOP:
            nexthop = attribute['nexthop']
        elif attribute['type'] == C.MULTI_EXIT_DISC:
            try:
                med = attribute['metric']
            except Exception:
                med = None
        elif attribute['type'] == C.LOCAL_PREF:
            try:
                local_pref = attribute['value']
            except Exception:
                local_pref = None
        elif attribute['type'] == C.ATOMIC_AGGREGATE:
            pass
        elif attribute['type'] == C.AGGREGATOR:
            pass
        elif attribute['type'] == C.COMMUNITY:
            communities = attribute['communities']
        elif attribute['type'] == C.ORIGINATOR_ID:
            originator_id = attribute['value']
        elif attribute['type'] == C.CLUSTER_LIST:
            cluster_list = attribute['value']
        elif attribute['type'] == C.MP_REACH_NLRI:
            nexthop = attribute['nexthop']
        elif attribute['type'] == C.MP_UNREACH_NLRI:
            pass
        elif attribute['type'] == C.EXTENDED_COMMUNITIES:
            pass
        else:
            pass
    if 'withdrawal' in update_entry:
        withdrawal = update_entry['withdrawal']
    else:
        withdrawal = False
    if 'age' in update_entry:
        age = update_entry['age']
    else:
        age = None

    return prefix, origin, as_path, nexthop, med, local_pref, atomic_aggregate, aggregator, communities, originator_id, cluster_list, withdrawal, age


def main():
    """Read GoBGP RIB JSON update lists from stdin and send individual entries
    to be parsed and fed into Mongo."""
    line_counter = 0
    for line in sys.stdin:
        try:
            update_list = json.loads(line)
            for update_entry in update_list:
                if 'error' in update_entry:
                    pass
                else:
                    # print(update_entry)
                    # build_objects(update_entry)
                    Prefix(build_json_update_entry(update_entry))
                    line_counter += 1
                    if line_counter % 5000 == 0:
                        print(".", end='', flush=True)
                    # print(new_prefix.origin_as.name)
                    # print(new_prefix.origin_as.prefixes[0].origin_as.name)
                    # print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_prefix.timestamp)))
                    # print(new_prefix.timestamp)
                    # pprint(vars(new_prefix))
                    # print(Prefix.ipv4_prefix_count)
                    # print(Prefix.ipv6_prefix_count)
        except Exception as err:
            print(err)
            pass
    # for asn, asn_obj in ASN.asn_dict.items():
    #     print(str(asn) + ": " + str(len(asn_obj.prefixes)) + ": " + asn_obj.name)
    # #     for prefix, prefix_obj in asn_obj.prefixes.items():
    # #         if len(prefix_obj.previous_as_paths) == 1:
    # #             print(prefix, prefix_obj.previous_as_paths)
    # #         # print(str(asn) + ":" + prefix + ":" + str(prefix_obj.withdrawal) + ":" + prefix_obj.origin_as.name)
    # #         pass
    # for prefix, prefix_obj in Prefix.prefix_dict.items():
    #     if len(prefix_obj.previous_as_paths) > 1:
    #         for path, timestamp in prefix_obj.previous_as_paths:
    #             print(prefix, path, timestamp)
    #     print()
    # for asn, asn_obj in ASN.asn_dict.items():
    #     print(str(asn) + " - " + asn_obj.name)
    #     for prefix, prefix_obj in asn_obj.prefixes.items():
    #         print(prefix)
    #         for path, epoch in prefix_obj.previous_as_paths:
    #             print(path, (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))))
    print()
    print()
    # print(len(ASN.asn_dict))
    # print(len(Prefix.prefix_dict))
    # # myasn = ASN.asn_dict.get(23752)
    for prefix, prefix_obj in ASN.asn_dict.get(3701).prefixes.items():
        print(prefix)
        for path, epoch in prefix_obj.previous_as_paths:
            print(path, (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))))
        # pprint(vars(prefix_obj))
        # print(prefix_obj.origin_as.name)
    for prefix, prefix_obj in Prefix.prefix_dict.items():
        if prefix_obj.communities and '3701:370' in prefix_obj.communities:
            for path, timestamp in prefix_obj.previous_as_paths:
                print(prefix_obj.origin_as.name, prefix, path, (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))))
            print()
    # for prefix, prefix_obj in Prefix.prefix_dict.items():

    print(len(ASN.asn_dict))
    print(len(Prefix.prefix_dict))


if __name__ == "__main__":
    sys.exit(main())
