from fastapi import FastAPI
import motor.motor_asyncio
import os
import json
import dns.resolver

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

app = FastAPI()

client = motor.motor_asyncio.AsyncIOMotorClient('mongodb', 27017)
db = client.bgp

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = None):
    return {"item_id": item_id, "q": q}


@app.get("/prefix_count/{version}")
async def prefix_count(version: int):
    """Given the IP version, return the number of prefixes in the database."""
    return await db.bgp.count_documents({'ip_version': version, 'active': True})


@app.get("/peer_count/")
async def peer_count():
    """Return the number of directly connected ASNs."""
    count = await db.bgp.distinct('nexthop_asn', {'active': True})
    return len(count)


@app.get("/peers")
async def get_peers():
    # peer_json = json.dumps(get_list_of(peers=True))
    # return peer_json
    return get_list_of(peers=True)


async def get_list_of(customers=False, peers=False, community=CUSTOMER_BGP_COMMUNITY):
    """Return a list of prefix dictionaries.  Specify which type of prefix to
    return by setting *customers* or *peers* to True."""
    if peers:
        query_results = {prefix['nexthop_asn'] for prefix in db.bgp.find({'active': True})}
    if customers:
        query_results = {prefix['nexthop_asn'] for prefix in db.bgp.find({'communities': community, 'active': True})}
    return [{'asn': asn if asn is not None else DEFAULT_ASN,  # Set "None" ASNs to default
                'name': asn_name_query(asn),
                'ipv4_origin_count': db.bgp.count_documents({'origin_asn': asn, 'ip_version': 4, 'active': True}),
                'ipv6_origin_count': db.bgp.count_documents({'origin_asn': asn, 'ip_version': 6, 'active': True}),
                'ipv4_nexthop_count': db.bgp.count_documents({'nexthop_asn': asn, 'ip_version': 4, 'active': True}),
                'ipv6_nexthop_count': db.bgp.count_documents({'nexthop_asn': asn, 'ip_version': 6, 'active': True}),
                'asn_count':  len(db.bgp.distinct('as_path.1', {'nexthop_asn': asn, 'active': True}))}
            for asn in query_results]


def asn_name_query(asn):
    """Given an *asn*, return the name."""
    if asn is None:
        asn = DEFAULT_ASN
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