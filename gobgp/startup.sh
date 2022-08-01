## Production
# /root/gobgp/gobgp monitor global rib -j | /var/tmp/gobgp_to_mongo.py
##
## Dev Test
# cat /var/tmp/log/bgp.dump.json | /var/tmp/gobgp_to_mongo.py
cat /var/tmp/log/new_v4_unicast_bgp.dump.json | /var/tmp/gobgp_to_mongo.py
##
### Dev Test - Dump to local file
# /root/gobgp/gobgp monitor global rib -j > /var/tmp/log/bgp.dump.json
