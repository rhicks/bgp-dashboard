## Production
/root/gobgp/gobgp monitor global rib -j | /var/tmp/gobgp_to_mongo.py
##
## Dev Test
# cat /var/tmp/log/bgp.dump.json | /var/tmp/gobgp_to_mongo.py
