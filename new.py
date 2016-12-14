#!/usr/bin/env python
'''
print_all.py - a script to print a MRT format data using mrtparse.
Copyright (C) 2016 greenHippo, LLC.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
Authors:
    Tetsumune KISO <t2mune@gmail.com>
    Yoshiyuki YAMAUCHI <info@greenhippo.co.jp>
    Nobuhiro ITOU <js333123@gmail.com>
'''

import sys
from optparse import OptionParser
from datetime import *
from mrtparse import *
import json
from collections import Counter


indt = 0
mrtjson = {}

def prerror(m):
    print('%s: %s' % (MRT_ERR_C[m.err], m.err_msg))
    if m.err == MRT_ERR_C['MRT Header Error']:
        buf = m.buf
    else:
        buf = m.buf[12:]
    s = ''
    for i in range(len(buf)):
        if isinstance(buf[i], str):
            s += '%02x ' % ord(buf[i])
        else:
            s += '%02x ' % buf[i]

        if (i + 1) % 16 == 0:
            print('    %s' % s)
            s = ''
        elif (i + 1) % 8 == 0:
            s += ' '
    if len(s):
        print('    %s' % s)

def prline(line):
    global indt
    print('    ' * indt + line)

def print_mrt(m):
    mrtjson = {}

    # global indt
    # indt = 0
    # prline('MRT Header')
    mrtjson['mrt_header'] = {}

    # indt += 1
    # prline('Timestamp: %d(%s)' % (m.ts, datetime.fromtimestamp(m.ts)))
    mrtjson['mrt_header']['timestamp'] = '%s' % datetime.fromtimestamp(m.ts)
    # prline('Type: %d(%s)' % (m.type, MRT_T[m.type]))
    mrtjson['mrt_header']['type'] = MRT_T[m.type]
    # prline('Subtype: %d(%s)' % (m.subtype, MRT_ST[m.type][m.subtype]))
    mrtjson['mrt_header']['subtype'] = MRT_ST[m.type][m.subtype]
    # prline('Length: %d' % m.len)
    mrtjson['mrt_header']['length'] = m.len

    if (   m.type == MRT_T['BGP4MP_ET']
        or m.type == MRT_T['ISIS_ET']
        or m.type == MRT_T['OSPFv3_ET']):
        # prline('Microsecond Timestamp: %d' % m.micro_ts)
        mrtjson['mrt_header']['micro_timestamp'] = m.micro_ts
    
    #print(json.dumps(mrtjson, indent=2, sort_keys=False))

def print_td(m):
    global indt
    indt = 0
    prline('%s' % MRT_T[m.type])

    indt += 1
    prline('View Number: %d' % m.td.view)
    prline('Sequence Number: %d' % m.td.seq)
    prline('Prefix: %s' % m.td.prefix)
    prline('Prefix length: %d' % m.td.plen)
    prline('Status: %d' % m.td.status)
    prline('Originated Time: %d(%s)' %
        (m.td.org_time,
         datetime.fromtimestamp(m.td.org_time)))
    prline('Peer IP Address: %s' % m.td.peer_ip)
    prline('Peer AS: %s' % m.td.peer_as)
    prline('Attribute Length: %d' % m.td.attr_len)
    for attr in m.td.attr:
        print_bgp_attr(attr, 1)

def print_td_v2(m):
    global indt
    indt = 0
    # prline('%s' % TD_V2_ST[m.subtype])
    # mrtjson = {}
    # mrtjson['%s' % TD_V2_ST[m.subtype]] = {}


    indt += 1
    if m.subtype == TD_V2_ST['PEER_INDEX_TABLE']:
        mrtjson['%s' % TD_V2_ST[m.subtype]] = {}
        # prline('Collector: %s' % m.peer.collector)
        mrtjson['%s' % TD_V2_ST[m.subtype]]['collector'] = m.peer.collector
        # prline('View Name Length: %d' % m.peer.view_len)
        # prline('View Name: %s' % m.peer.view)
        # prline('Peer Count: %d' % m.peer.count)
        #mrtjson['collector'] = m.peer.collector
        mrtjson['%s' % TD_V2_ST[m.subtype]]['view_name_length'] = m.peer.view_len
        mrtjson['%s' % TD_V2_ST[m.subtype]]['view_name'] = m.peer.view
        mrtjson['%s' % TD_V2_ST[m.subtype]]['peer_count'] = m.peer.count
        
        for entry in m.peer.entry:
            # prline('Peer Type: 0x%02x' % entry.type)
            mrtjson['%s' % TD_V2_ST[m.subtype]]['peer_type'] = entry.type
            # prline('Peer BGP ID: %s' % entry.bgp_id)
            mrtjson['%s' % TD_V2_ST[m.subtype]]['peer_bgp_id'] = entry.bgp_id
            # prline('Peer IP Address: %s' % entry.ip)
            mrtjson['%s' % TD_V2_ST[m.subtype]]['peer_ip'] = entry.ip
            # prline('Peer AS: %s' % entry.asn)
            mrtjson['%s' % TD_V2_ST[m.subtype]]['peer_asn'] = entry.asn

    elif ( m.subtype == TD_V2_ST['RIB_IPV4_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV4_MULTICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_MULTICAST']):
        mrtjson['rib'] = {}
        mrtjson['rib']['rib_type'] = TD_V2_ST[m.subtype]
        # prline('Sequence Number: %d' % m.rib.seq)
        mrtjson['rib']['sequence_number'] = m.rib.seq
        # prline('Prefix Length: %d' % m.rib.plen)
        mrtjson['rib']['prefix_length'] = m.rib.plen
        # prline('Prefix: %s' % m.rib.prefix)
        mrtjson['rib']['prefix'] = m.rib.prefix
        # prline('Entry Count: %d' % m.rib.count)
        mrtjson['rib']['entry_count'] = m.rib.count

        for entry in m.rib.entry:
            indt = 1
            # prline('Peer Index: %d' % entry.peer_index)
            mrtjson['rib']['peer_index'] = entry.peer_index
            # prline('Originated Time: %d(%s)' % (entry.org_time, datetime.fromtimestamp(entry.org_time)))
            mrtjson['rib']['originated_time'] = '%s' % datetime.fromtimestamp(entry.org_time)
            # prline('Attribute Length: %d' % entry.attr_len)
            mrtjson['rib']['attribute_length'] = entry.attr_len
            for attr in entry.attr:
                print_bgp_attr(attr, mrtjson['rib'])

    elif m.subtype == TD_V2_ST['RIB_GENERIC']:
        prline('Sequence Number: %d' % m.rib.seq)
        prline('AFI: %d(%s)' % (m.rib.afi, AFI_T[m.rib.afi]))
        prline('SAFI: %d(%s)' % (m.rib.safi, SAFI_T[m.rib.safi]))
        for nlri in m.rib.nlri:
            print_nlri(nlri, 'NLRI', m.rib.safi)
        prline('Entry Count: %d' % m.rib.count)

        for entry in m.rib.entry:
            indt = 1
            prline('Peer Index: %d' % entry.peer_index)
            prline('Originated Time: %d(%s)' %
                (entry.org_time,
                 datetime.fromtimestamp(entry.org_time)))
            prline('Attribute Length: %d' % entry.attr_len)
            for attr in entry.attr:
                print_bgp_attr(attr, 1)


def print_bgp4mp(m):
    # global indt
    # indt = 0
    # prline('%s' % BGP4MP_ST[m.subtype])
    mrtjson['%s' % BGP4MP_ST[m.subtype]] = {}


    # indt += 1
    # prline('Peer AS Number: %s' % m.bgp.peer_as)
    mrtjson['%s' % BGP4MP_ST[m.subtype]]['peer_asn'] = m.bgp.peer_as
    # prline('Local AS Number: %s' % m.bgp.local_as)
    mrtjson['%s' % BGP4MP_ST[m.subtype]]['local_asn'] = m.bgp.local_as
    # prline('Interface Index: %d' % m.bgp.ifindex)
    mrtjson['%s' % BGP4MP_ST[m.subtype]]['ifindex'] = m.bgp.ifindex
    # prline('Address Family: %d(%s)' % (m.bgp.af, AFI_T[m.bgp.af]))
    mrtjson['%s' % BGP4MP_ST[m.subtype]]['address_family'] = AFI_T[m.bgp.af]
    # prline('Peer IP Address: %s' % m.bgp.peer_ip)
    mrtjson['%s' % BGP4MP_ST[m.subtype]]['peer_ip'] = m.bgp.peer_ip
    # prline('Local IP Address: %s' % m.bgp.local_ip)
    mrtjson['%s' % BGP4MP_ST[m.subtype]]['local_ip'] = m.bgp.local_ip

    if (   m.subtype == BGP4MP_ST['BGP4MP_STATE_CHANGE']
        or m.subtype == BGP4MP_ST['BGP4MP_STATE_CHANGE_AS4']):
        # prline('Old State: %d(%s)' % (m.bgp.old_state, BGP_FSM[m.bgp.old_state]))
        mrtjson['%s' % BGP4MP_ST[m.subtype]]['old_state'] = BGP_FSM[m.bgp.old_state]
        # prline('New State: %d(%s)' % (m.bgp.new_state, BGP_FSM[m.bgp.new_state]))
        mrtjson['%s' % BGP4MP_ST[m.subtype]]['new_state'] = BGP_FSM[m.bgp.new_state]

    elif ( m.subtype == BGP4MP_ST['BGP4MP_MESSAGE']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL']
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']):
        print_bgp_msg(m.bgp.msg, m.subtype)

def print_bgp_msg(msg, subtype):
    # global indt
    # indt = 0
    # # prline('BGP Message')
    # 
    # indt += 1
    # # prline('Marker: -- ignored --')
    # prline('Length: %d' % msg.len)
    mrtjson['%s' % BGP4MP_ST[subtype]]['length'] = msg.len
    # prline('Type: %d(%s)' % (msg.type, BGP_MSG_T[msg.type]))
    mrtjson['%s' % BGP4MP_ST[subtype]]['type'] = BGP_MSG_T[msg.type]
    mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]] = {}


    if msg.type == BGP_MSG_T['OPEN']:
        # prline('Version: %d' % msg.ver)
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['version'] = msg.ver
        # prline('My AS: %d' % msg.my_as)
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['my_asn'] = msg.my_as
        # prline('Hold Time: %d' % msg.holdtime)
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['holdtime'] = msg.holdtime
        # prline('BGP Identifier: %s' % msg.bgp_id)
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['bgp_id'] = msg.bgp_id
        # prline('Optional Parameter Length: %d' % msg.opt_len)
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['options_len'] = msg.opt_len
    
        for opt in msg.opt_params:
            print_bgp_opt_params(opt)
    
    elif msg.type == BGP_MSG_T['UPDATE']:
        # prline('Withdrawn Routes Length: %d' % msg.wd_len)
        if msg.wd_len > 0:
            mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['withdrawn_len'] = msg.wd_len
            for withdrawn in msg.withdrawn:
                print_nlri(withdrawn, 'withdraw', mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]])
        else:
            # prline('Total Path Attribute Length: %d' % msg.attr_len)
            mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['path_attrib_len'] = msg.attr_len
            for attr in msg.attr:
                print_bgp_attr(attr, mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]])
            indt = 1
            for nlri in msg.nlri:
                print_nlri(nlri, 'update', mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]])
    
    elif msg.type == BGP_MSG_T['NOTIFICATION']:
        #prline('Error Code: %d(%s)' % (msg.err_code, BGP_ERR_C[msg.err_code]))
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['error_code'] = BGP_ERR_C[msg.err_code]
        #prline('Error Subcode: %d(%s)' % (msg.err_subcode, BGP_ERR_SC[msg.err_code][msg.err_subcode]))
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['error_subcode'] = BGP_ERR_SC[msg.err_code][msg.err_subcode]
        #prline('Data: %s' % msg.data)
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['data'] = msg.data
    
    elif msg.type == BGP_MSG_T['ROUTE-REFRESH']:
        # prline('AFI: %d(%s)' % (msg.afi, AFI_T[msg.afi]))
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['afi'] = AFI_T[msg.afi]
        # prline('Reserved: %d' % (msg.rsvd))
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['reserved'] = msg.rsvd
        # prline('SAFI: %d(%s)' % (msg.safi, SAFI_T[msg.safi]))
        mrtjson['%s' % BGP4MP_ST[subtype]][BGP_MSG_T[msg.type]]['safi'] = AFI_T[msg.safi]

def print_bgp_opt_params(opt):
    global indt
    indt = 1
    prline('Parameter Type/Length: %d/%d' % (opt.type, opt.len))

    indt += 1
    prline('%s' % BGP_OPT_PARAMS_T[opt.type])

    if opt.type != BGP_OPT_PARAMS_T['Capabilities']:
        return

    indt += 1
    prline('Capability Code: %d(%s)' %
        (opt.cap_type, BGP_CAP_C[opt.cap_type]))
    prline('Capability Length: %d' % opt.cap_len)

    if opt.cap_type == BGP_CAP_C['Multiprotocol Extensions for BGP-4']:
        prline('AFI: %d(%s)' %
            (opt.multi_ext['afi'], AFI_T[opt.multi_ext['afi']]))
        prline('Reserved: %d' % opt.multi_ext['rsvd'])
        prline('SAFI: %d(%s)' %
            (opt.multi_ext['safi'], SAFI_T[opt.multi_ext['safi']]))

    elif opt.cap_type == BGP_CAP_C['Route Refresh Capability for BGP-4']:
        pass

    elif opt.cap_type == BGP_CAP_C['Outbound Route Filtering Capability']:
        prline('AFI: %d(%s)' %
            (opt.orf['afi'], AFI_T[opt.orf['afi']]))
        prline('Reserved: %d' % opt.orf['rsvd'])
        prline('SAFI: %d(%s)' %
            (opt.orf['safi'], SAFI_T[opt.orf['safi']]))
        prline('Number: %d' % opt.orf['number'])

        for entry in opt.orf['entry']:
            prline('Type: %d' % entry['type'])
            prline('Send Receive: %d(%s)' %
                (entry['send_recv'], ORF_SEND_RECV[entry['send_recv']]))

    elif opt.cap_type == BGP_CAP_C['Graceful Restart Capability']:
        prline('Restart Flags: 0x%x' %
            opt.graceful_restart['flag'])
        prline('Restart Time in Seconds: %d' %
            opt.graceful_restart['sec'])

        for entry in opt.graceful_restart['entry']:
            prline('AFI: %d(%s)' %
                (entry['afi'], AFI_T[entry['afi']]))
            prline('SAFI: %d(%s)' %
                (entry['safi'], SAFI_T[entry['safi']]))
            prline('Flag: 0x%02x' % entry['flag'])

    elif opt.cap_type == BGP_CAP_C['Support for 4-octet AS number capability']:
        prline('AS Number: %s' % opt.support_as4)

    elif opt.cap_type == BGP_CAP_C['ADD-PATH Capability']:
        for entry in opt.add_path:
            prline('AFI: %d(%s)' %
                (entry['afi'], AFI_T[entry['afi']]))
            prline('SAFI: %d(%s)' %
                (entry['safi'], SAFI_T[entry['safi']]))
            prline('Send Receive: %d(%s)' %
                (entry['send_recv'],
                ADD_PATH_SEND_RECV[entry['send_recv']]))

def print_bgp_attr(attr, d):
    #global indt
    #indt = n
    # prline('Path Attribute Flags/Type/Length: 0x%02x/%d/%d' %
    #     (attr.flag, attr.type, attr.len))

    #indt += 1
    line = '%s' % BGP_ATTR_T[attr.type]
    if attr.type == BGP_ATTR_T['ORIGIN']:
        # prline(line + ': %d(%s)' % (attr.origin, ORIGIN_T[attr.origin]))
        d['origin'] = ORIGIN_T[attr.origin]
    elif attr.type == BGP_ATTR_T['AS_PATH']:
        # prline(line)
        #indt += 1
        for path_seg in attr.as_path:
            # prline('Path Segment Type: %d(%s)' %
            #     (path_seg['type'], AS_PATH_SEG_T[path_seg['type']]))
            d['as_path_seg_type'] = AS_PATH_SEG_T[path_seg['type']]
            # prline('Path Segment Length: %d' % path_seg['len'])
            d['as_path_length'] = path_seg['len']
            # prline('Path Segment Value: %s' % ' '.join(path_seg['val']))
            d['as_path'] = map(int, path_seg['val'])
    elif attr.type == BGP_ATTR_T['NEXT_HOP']:
        # prline(line + ': %s' % attr.next_hop)
        d['next_hop'] = attr.next_hop
    elif attr.type == BGP_ATTR_T['MULTI_EXIT_DISC']:
        # prline(line + ': %d' % attr.med)
        d['multi_exit_disc'] = attr.med
    elif attr.type == BGP_ATTR_T['LOCAL_PREF']:
        # prline(line + ': %d' % attr.local_pref)
        d['local_pref'] = attr.local_pref
    elif attr.type == BGP_ATTR_T['ATOMIC_AGGREGATE']:
        # prline(line)
        d['atomic_aggregate'] = line
    elif attr.type == BGP_ATTR_T['AGGREGATOR']:
        # prline(line + ': %s %s' % (attr.aggr['asn'], attr.aggr['id']))
        d['aggregator'] = '%s %s' % (attr.aggr['asn'], attr.aggr['id'])
    elif attr.type == BGP_ATTR_T['COMMUNITY']:
        # prline(line + ': %s' % ' '.join(attr.comm))
        d['community'] = '%s' % ' '.join(attr.comm)
    elif attr.type == BGP_ATTR_T['ORIGINATOR_ID']:
        # prline(line + ': %s' % attr.org_id)
        d['originator_id'] = attr.org_id
    elif attr.type == BGP_ATTR_T['CLUSTER_LIST']:
        # prline(line + ': %s' % ' '.join(attr.cl_list))
        d['cluster_list'] = '%s' % ' '.join(attr.cl_list)
    elif attr.type == BGP_ATTR_T['MP_REACH_NLRI']:
        # prline(line)
        # indt += 1
        d['mp_reach_nlri'] = {}
        if 'afi' in attr.mp_reach:
            # prline('AFI: %d(%s)' %
            #     (attr.mp_reach['afi'], AFI_T[attr.mp_reach['afi']]))
            d['mp_reach_nlri']['afi'] = '%s' % AFI_T[attr.mp_reach['afi']]
        
        if 'safi' in attr.mp_reach:
            # prline('SAFI: %d(%s)' %
                # (attr.mp_reach['safi'], SAFI_T[attr.mp_reach['safi']]))
            d['mp_reach_nlri']['safi'] = '%s' % SAFI_T[attr.mp_reach['safi']]
        
            if (   attr.mp_reach['safi'] == SAFI_T['L3VPN_UNICAST']
                or attr.mp_reach['safi'] == SAFI_T['L3VPN_MULTICAST']):
                # prline('Route Distinguisher: %s' % attr.mp_reach['rd'])
                d['mp_reach_nlri']['route_distinguisher'] = '%s' % attr.mp_reach['rd']

        # prline('Length: %d' % attr.mp_reach['nlen'])
        d['mp_reach_nlri']['length'] = attr.mp_reach['nlen']
        if 'next_hop' not in attr.mp_reach:
            return
        next_hop = " ".join(attr.mp_reach['next_hop'])
        # prline('Next-Hop: %s' % next_hop)
        d['mp_reach_nlri']['next-hop'] = next_hop

        if 'nlri' in attr.mp_reach:
            for nlri in attr.mp_reach['nlri']:
                # print(d)
                d['mp_reach_nlri']['nlri'] = [attr.mp_reach['safi']]
                # print(d)
                print_nlri(nlri, 'UPDATE', d)
    elif attr.type == BGP_ATTR_T['MP_UNREACH_NLRI']:
        # prline(line)
        # indt += 1
        d['mp_unreach_nlri'] = {}
        # prline('AFI: %d(%s)' %
        #     (attr.mp_unreach['afi'], AFI_T[attr.mp_unreach['afi']]))
        d['mp_unreach_nlri']['afi'] = '%s' % AFI_T[attr.mp_unreach['afi']]
        # prline('SAFI: %d(%s)' %
        #     (attr.mp_unreach['safi'], SAFI_T[attr.mp_unreach['safi']]))
        d['mp_unreach_nlri']['afi'] = '%s' % AFI_T[attr.mp_unreach['afi']]

        for withdrawn in attr.mp_unreach['withdrawn']:
            d['mp_unreach_nlri']['withdrawn'] = attr.mp_unreach['safi']
            print_nlri(withdrawn, 'withdrawn', d)
    elif attr.type == BGP_ATTR_T['EXTENDED_COMMUNITIES']:
        ext_comm_list = []
        for ext_comm in attr.ext_comm:
            ext_comm_list.append('0x%016x' % ext_comm)
        prline(line + ': %s' % ' '.join(ext_comm_list))
    elif attr.type == BGP_ATTR_T['AS4_PATH']:
        prline(line)
        indt += 1
        for path_seg in attr.as4_path:
            prline('Path Segment Type: %d(%s)' %
                (path_seg['type'], AS_PATH_SEG_T[path_seg['type']]))
            prline('Path Segment Length: %d' % path_seg['len'])
            prline('Path Segment Value: %s' % ' '.join(path_seg['val']))
    elif attr.type == BGP_ATTR_T['AS4_AGGREGATOR']:
        prline(line + ': %s %s' % (attr.as4_aggr['asn'], attr.as4_aggr['id']))
    elif attr.type == BGP_ATTR_T['AIGP']:
        prline(line)
        indt += 1
        for aigp in attr.aigp:
            prline('Type: %d' % aigp['type'])
            prline('Length: %d' % aigp['len'])
            prline('Value: %d' % aigp['val'])
    elif attr.type == BGP_ATTR_T['ATTR_SET']:
        prline(line)
        indt += 1
        prline('Origin AS: %s' % attr.attr_set['origin_as'])
        for attr in attr.attr_set['attr']:
            print_bgp_attr(attr, 3)
    elif attr.type == BGP_ATTR_T['LARGE_COMMUNITY']:
        prline(line + ': %s' % ' '.join(attr.large_comm))
    else:
        line += ': 0x'
        for c in attr.val:
            if isinstance(c, str):
                c = ord(c)
            line += '%02x' % c
        prline(line)

def print_nlri(nlri, action, d, *args):
    global indt
    safi = args[0] if len(args) > 0 else 0

    if (   safi == SAFI_T['L3VPN_UNICAST']
        or safi == SAFI_T['L3VPN_MULTICAST']):
        prline('%s' % title)
        indt += 1
        plen = nlri.plen - (len(nlri.label) * 3 + 8) * 8
        l_all = []
        l_val = []
        for label in nlri.label:
            l_all.append('0x%06x' % label)
            l_val.append(str(label >> 4))
        if nlri.path_id is not None:
            prline('Path Identifier: %d' % nlri.path_id)
        prline('Label: %s(%s)' % (' '.join(l_all), ' '.join(l_val)))
        prline('Route Distinguisher: %s' % nlri.rd)
        prline('Prefix: %s/%d' % (nlri.prefix, plen))
        indt -= 1
    else:
        if nlri.path_id is not None:
            prline('%s' % title)
            indt += 1
            prline('Path Identifier: %d' % nlri.path_id)
            prline('Prefix: %s/%d' % (nlri.prefix, nlri.plen))
            indt -= 1
        else:
            #print(d)
            #prline('%s: %s/%d' % (title, nlri.prefix, nlri.plen))
            # "prefix": "['__doc__', '__init__', '__module__', '__slots__', 
            # 'buf', 'chk_buf', 'is_dup', 'is_valid', 'label', 'p', 'path_id',
            # 'plen', 'prefix', 'rd', 'unpack', 'unpack_l3vpn', 'val_addr', 
            # 'val_asn', 'val_bytes', 'val_nlri', 'val_num', 'val_rd', 'val_str']/48"
            d['action'] = action
            d['prefix'] = '%s/%d' % (nlri.prefix, nlri.plen)

def main():
    if len(sys.argv) != 2:
        print('Usage: %s FILENAME' % sys.argv[0])
        exit(1)

    d = Reader(sys.argv[1])

    # if you want to use 'asdot+' or 'asdot' for AS numbers,
    # comment out either line below.
    # default is 'asplain'.
    #
    # as_repr(AS_REPR['asdot+'])
    # as_repr(AS_REPR['asdot'])
    arf = []
    for m in d:
        m = m.mrt
        #mrtjson = {}
        #print('---------------------------------------------------------------')
        if m.err == MRT_ERR_C['MRT Header Error']:
            prerror(m)
            continue
        print_mrt(m)

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
        
        #print(json.dumps(mrtjson, indent=4, sort_keys=True))
    #     if 'rib' in mrtjson:
    #         arf.append(mrtjson['rib']['prefix_length'])
    # 
    # print(Counter(arf).items())
    # print(set(arf))


if __name__ == '__main__':
    main()
