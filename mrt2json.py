#!/usr/bin/env python2

import sys
from optparse import OptionParser
from datetime import *
from mrtparse import *
import json

mrtjson = {}

def print_bgp4mp(m):
    #print('%s' % BGP4MP_ST[m.subtype])
    mrtjson['subtype'] = '%s' % BGP4MP_ST[m.subtype]
    #print('Peer AS Number: %s' % m.bgp.peer_as)
    mrtjson['peer_as'] =  '%s' % m.bgp.peer_as
    # print('Local AS Number: %s' % m.bgp.local_as)
    mrtjson['local_as'] = '%s' % m.bgp.local_as
    # print('Interface Index: %d' % m.bgp.ifindex)
    mrtjson['ifindex'] = '%d' % m.bgp.ifindex
    # print('Address Family: %d(%s)' % (m.bgp.af, AFI_T[m.bgp.af]))
    mrtjson['af'] = '%d(%s)' % (m.bgp.af, AFI_T[m.bgp.af])
    # print('Peer IP Address: %s' % m.bgp.peer_ip)
    mrtjson['peer_ip'] = '%s' % m.bgp.peer_ip
    # print('Local IP Address: %s' % m.bgp.local_ip)
    mrtjson['local_ip'] = '%s' % m.bgp.local_ip

    
    if (   m.subtype == BGP4MP_ST['BGP4MP_STATE_CHANGE']
        or m.subtype == BGP4MP_ST['BGP4MP_STATE_CHANGE_AS4']):
        print('Old State: %d(%s)' %
            (m.bgp.old_state, BGP_FSM[m.bgp.old_state]))
        print('New State: %d(%s)' %
            (m.bgp.new_state, BGP_FSM[m.bgp.new_state]))
    
    elif ( m.subtype == BGP4MP_ST['BGP4MP_MESSAGE']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']):
        mrtjson['rib_entry'] = {}
        mrtjson['rib_entry']['attributes'] = {}
        print_bgp_msg(m.bgp.msg, m.subtype)
    
    print(json.dumps(mrtjson, indent=2, sort_keys=False))
    

def print_bgp_msg(msg, subtype):
    #print('BGP Message')

    #print('Marker: -- ignored --')
    #print('Length: %d' % msg.len)
    print('Type: %d(%s)' % (msg.type, BGP_MSG_T[msg.type]))

    if msg.type == BGP_MSG_T['OPEN']:
        print('Version: %d' % msg.ver)
        print('My AS: %d' % msg.my_as)
        print('Hold Time: %d' % msg.holdtime)
        print('BGP Identifier: %s' % msg.bgp_id)
        print('Optional Parameter Length: %d' % msg.opt_len)

        for opt in msg.opt_params:
            print_bgp_opt_params(opt)

    elif msg.type == BGP_MSG_T['UPDATE']:
        if msg.wd_len > 0:
            mrtjson['action'] = '%s' % 'withdrawn'
            #print('Withdrawn Routes Length: %d' % msg.wd_len)
            for withdrawn in msg.withdrawn:
                #print('%s/%d' % (withdrawn.prefix, withdrawn.plen))
                mrtjson['withdrawn'] = '%s/%d' % (withdrawn.prefix, withdrawn.plen)
                #print_nlri(withdrawn, 'Withdrawn Routes')
        else:
            mrtjson['action'] = '%s' % 'update'
        #print('Total Path Attribute Length: %d' % msg.attr_len)
        for attr in msg.attr:
            print_bgp_attr(attr)

        for nlri in msg.nlri:
            print_nlri(nlri, 'NLRI')

    elif msg.type == BGP_MSG_T['NOTIFICATION']:
        print('Error Code: %d(%s)' %
            (msg.err_code, BGP_ERR_C[msg.err_code]))
        print('Error Subcode: %d(%s)' %
            (msg.err_subcode, BGP_ERR_SC[msg.err_code][msg.err_subcode]))
        print('Data: %s' % msg.data)

    elif msg.type == BGP_MSG_T['ROUTE-REFRESH']:
        print('AFI: %d(%s)' % (msg.afi, AFI_T[msg.afi]))
        print('Reserved: %d' % (msg.rsvd))
        print('SAFI: %d(%s)' % (msg.safi, SAFI_T[msg.safi]))
        
def print_nlri(nlri, title, *args):
    safi = args[0] if len(args) > 0 else 0

    if (   safi == SAFI_T['L3VPN_UNICAST']
        or safi == SAFI_T['L3VPN_MULTICAST']):
        print('%s' % title)
        plen = nlri.plen - (len(nlri.label) * 3 + 8) * 8
        l_all = []
        l_val = []
        for label in nlri.label:
            l_all.append('0x%06x' % label)
            l_val.append(str(label >> 4))
        if nlri.path_id is not None:
            print('Path Identifier: %d' % nlri.path_id)
        print('Label: %s(%s)' % (' '.join(l_all), ' '.join(l_val)))
        print('Route Distinguisher: %s' % nlri.rd)
        print('Prefix: %s/%d' % (nlri.prefix, plen))
    else:
        if nlri.path_id is not None:
            print('%s' % title)
            print('Path Identifier: %d' % nlri.path_id)
            print('Prefix: %s/%d' % (nlri.prefix, nlri.plen))
        else:
            print('%s: %s/%d' % (title, nlri.prefix, nlri.plen))
            mrtjson[title] = '%s/%d' % (nlri.prefix, nlri.plen)
            
            


def print_bgp_attr(attr):
    #print(attr.type)
    line = '%s' % BGP_ATTR_T[attr.type]
    if attr.type == BGP_ATTR_T['ORIGIN']:
        mrtjson['rib_entry']['attributes']['origin'] = '%d(%s)' % (attr.origin, ORIGIN_T[attr.origin])
    elif attr.type == BGP_ATTR_T['AS_PATH']:
        for path_seg in attr.as_path:
            mrtjson['rib_entry']['attributes']['as_path'] = map(int, path_seg['val'])
            mrtjson['rib_entry']['attributes']['as_path_type'] = '%d(%s)' % (path_seg['type'], AS_PATH_SEG_T[path_seg['type']])
            mrtjson['rib_entry']['attributes']['as_path_length'] = path_seg['len']
    # elif attr.type == BGP_ATTR_T['AS4_PATH']:
    #     for path_seg in attr.as4_path:
    #         mrtjson['rib_entry']['attributes']['as_path'] = map(int, path_seg['val'])
    #         mrtjson['rib_entry']['attributes']['as_path_type'] = '%d(%s)' % (path_seg['type'], AS_PATH_SEG_T[path_seg['type']])
    #         mrtjson['rib_entry']['attributes']['as_path_length'] = path_seg['len']
    elif attr.type == BGP_ATTR_T['NEXT_HOP']:
        mrtjson['rib_entry']['attributes']['nexthop'] = '%s' % attr.next_hop
    elif attr.type == BGP_ATTR_T['MULTI_EXIT_DISC']:
        mrtjson['rib_entry']['attributes']['med'] = '%s' % attr.med
    elif attr.type == BGP_ATTR_T['LOCAL_PREF']:
        mrtjson['rib_entry']['attributes']['med'] = '%s' % attr.local_pref
    elif attr.type == BGP_ATTR_T['ATOMIC_AGGREGATE']:
        mrtjson['rib_entry']['attributes']['atomic_aggregate'] = line
    elif attr.type == BGP_ATTR_T['AGGREGATOR']:
        mrtjson['rib_entry']['attributes']['aggregator'] = '%s %s' % (attr.aggr['asn'], attr.aggr['id'])
    elif attr.type == BGP_ATTR_T['COMMUNITY']:
        mrtjson['rib_entry']['attributes']['community'] = '%s' % ' '.join(attr.comm)
    elif attr.type == BGP_ATTR_T['ORIGINATOR_ID']:
        mrtjson['rib_entry']['attributes']['originator_id'] = '%s' % attr.org_id
    elif attr.type == BGP_ATTR_T['CLUSTER_LIST']:
        mrtjson['rib_entry']['attributes']['cluster_list'] = '%s' % ' '.join(attr.cl_list)
    # elif attr.type == BGP_ATTR_T['MP_REACH_NLRI']:
    #     print(line)
    #     if 'afi' in attr.mp_reach:
    #         print('AFI: %d(%s)' %
    #             (attr.mp_reach['afi'], AFI_T[attr.mp_reach['afi']]))
    # 
    #     if 'safi' in attr.mp_reach:
    #         print('SAFI: %d(%s)' %
    #             (attr.mp_reach['safi'], SAFI_T[attr.mp_reach['safi']]))
    # 
    #         if (   attr.mp_reach['safi'] == SAFI_T['L3VPN_UNICAST']
    #             or attr.mp_reach['safi'] == SAFI_T['L3VPN_MULTICAST']):
    #             print('Route Distinguisher: %s' % attr.mp_reach['rd'])
    # 
    #     print('Length: %d' % attr.mp_reach['nlen'])
    #     if 'next_hop' not in attr.mp_reach:
    #         return
    #     next_hop = " ".join(attr.mp_reach['next_hop'])
    #     print('Next-Hop: %s' % next_hop)
    # 
    #     if 'nlri' in attr.mp_reach:
    #         for nlri in attr.mp_reach['nlri']:
    #             print_nlri(nlri, 'NLRI', attr.mp_reach['safi'])
    # elif attr.type == BGP_ATTR_T['MP_UNREACH_NLRI']:
    #     print(line)
    #     indt += 1
    #     print('AFI: %d(%s)' %
    #         (attr.mp_unreach['afi'], AFI_T[attr.mp_unreach['afi']]))
    #     print('SAFI: %d(%s)' %
    #         (attr.mp_unreach['safi'], SAFI_T[attr.mp_unreach['safi']]))
    # 
    #     for withdrawn in attr.mp_unreach['withdrawn']:
    #         print_nlri(withdrawn, 'Withdrawn Routes', attr.mp_unreach['safi'])
    # elif attr.type == BGP_ATTR_T['EXTENDED_COMMUNITIES']:
    #     ext_comm_list = []
    #     for ext_comm in attr.ext_comm:
    #         ext_comm_list.append('0x%016x' % ext_comm)
    #     print(line + ': %s' % ' '.join(ext_comm_list))
    # elif attr.type == BGP_ATTR_T['AS4_PATH']:
    #     print(line)
    #     indt += 1
    #     for path_seg in attr.as4_path:
    #         print('Path Segment Type: %d(%s)' %
    #             (path_seg['type'], AS_PATH_SEG_T[path_seg['type']]))
    #         print('Path Segment Length: %d' % path_seg['len'])
    #         print('Path Segment Value: %s' % ' '.join(path_seg['val']))
    # elif attr.type == BGP_ATTR_T['AS4_AGGREGATOR']:
    #     print(line + ': %s %s' % (attr.as4_aggr['asn'], attr.as4_aggr['id']))
    # elif attr.type == BGP_ATTR_T['AIGP']:
    #     print(line)
    #     indt += 1
    #     for aigp in attr.aigp:
    #         print('Type: %d' % aigp['type'])
    #         print('Length: %d' % aigp['len'])
    #         print('Value: %d' % aigp['val'])
    # elif attr.type == BGP_ATTR_T['ATTR_SET']:
    #     print(line)
    #     indt += 1
    #     print('Origin AS: %s' % attr.attr_set['origin_as'])
    #     for attr in attr.attr_set['attr']:
    #         print_bgp_attr(attr, 3)
    # elif attr.type == BGP_ATTR_T['LARGE_COMMUNITY']:
    #     print(line + ': %s' % ' '.join(attr.large_comm))
    else:
        line += ': 0x'
        for c in attr.val:
            if isinstance(c, str):
                c = ord(c)
            line += '%02x' % c
        mrtjson['rib_entry']['attributes']['originator_id'] = line


def print_td_v2(m):
    # prline('%s' % TD_V2_ST[m.subtype])

    if m.subtype == TD_V2_ST['PEER_INDEX_TABLE']:
        # mrtjson['collector'] = m.peer.collector
        # mrtjson['view_name_length'] = m.peer.view_len
        # mrtjson['view_name'] = m.peer.view
        # mrtjson['peer_count'] = m.peer.count
        # 
        for entry in m.peer.entry:
            mrtjson['peer'] = {'peer_type': entry.type,
                               'peer_bgp_id': entry.bgp_id,
                               'peer_ip': entry.ip,
                               'peer_asn': entry.asn}

    if ( m.subtype == TD_V2_ST['RIB_IPV4_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV4_MULTICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_MULTICAST']):
        mrtjson['rib_seq_num'] = m.rib.seq
        mrtjson['prefix_length'] = m.rib.plen
        mrtjson['prefix'] = m.rib.prefix
        mrtjson['entry_count'] = m.rib.count
    
        for entry in m.rib.entry:
            mrtjson['rib_entry'] = {
                'peer_index': entry.peer_index,
                'org_time': '%s' % datetime.fromtimestamp(entry.org_time),
                'attr_len': entry.attr_len
            }
            mrtjson['rib_entry']['attributes'] = {}
            for attr in entry.attr:
                print_bgp_attr(attr)
    
        print(json.dumps(mrtjson, indent=2, sort_keys=False))


def main():
    if len(sys.argv) != 2:
        print('Usage: %s FILENAME' % sys.argv[0])
        exit(1)

    d = Reader(sys.argv[1])
    
    for m in d:
        m = m.mrt
        print('---------------------------------------------------------------')
        mrtjson = None
        #print(mrtjson)
        if m.err == MRT_ERR_C['MRT Header Error']:
            prerror(m)
            continue
        #print_mrt(m)

        if m.err == MRT_ERR_C['MRT Data Error']:
            prerror(m)
            continue
        if m.type == MRT_T['TABLE_DUMP']:
            print_td(m)
        elif m.type == MRT_T['TABLE_DUMP_V2']:
            print_td_v2(m)
        elif ( m.type == MRT_T['BGP4MP']
            or m.type == MRT_T['BGP4MP_ET']):
            print_bgp4mp(m)

if __name__ == '__main__':
    main()
