import logging
logging.basicConfig(level=logging.CRITICAL)
# logging.basicConfig(level=logging.DEBUG)

_DEFAULT_ASN = 3701
# BGP Attributes
PREFIX = 0
ORIGIN = 1
AS_PATH = 2
NEXT_HOP = 3
MULTI_EXIT_DISC = 4
LOCAL_PREF = 5
ATOMIC_AGGREGATE = 6
AGGREGATOR = 7
COMMUNITY = 8
ORIGINATOR_ID = 9
CLUSTER_LIST = 10
DPA = 11
ADVERTISER = 12
CLUSTER_ID = 13
MP_REACH_NLRI = 14
MP_UNREACH_NLRI = 15
EXTENDED_COMMUNITIES = 16
# UPDATE CODES
OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
# ORIGIN CODES
IGP = 0
EGP = 1
INCOMPLETE = 2
#
WITHDRAWAL = 11
AGE = 12

# FROM Flask
_DEFAULT_ASN = 3701
_CUSTOMER_BGP_COMMUNITY = '3701:370'
_TRANSIT_BGP_COMMUNITY = '3701:380'
_PEER_BGP_COMMUNITY = '3701:39.'
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

