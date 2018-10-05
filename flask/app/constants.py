# DEFAULTS - UPDATE ACCORDINGLY
DEFAULT_ASN = 3701
CUSTOMER_BGP_COMMUNITY = '3701:370'  # Prefixes learned from directly connected customers
TRANSIT_BGP_COMMUNITY = '3701:380'  # Prefixes learned from *paid* transit providers
PEER_BGP_COMMUNITY = '3701:39.'  # Prefixes learned from bilateral peers and exchanges
BGP_COMMUNITY_MAP = {
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
