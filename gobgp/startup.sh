# echo "starting sleep"
# sleep 30s
# echo "leaving sleep"
# echo "dumping ipv6 rib"
# gobgp global rib -a ipv6 -j > /var/tmp/log/ipv6-rib.json
# echo "dumping ipv4 rib"
# gobgp global rib -a ipv4 -j > /var/tmp/log/ipv4-rib.json
cat /dev/null > /var/tmp/log/updates.json
/usr/bin/tail -f -n +1 /var/tmp/log/updates.json | /var/tmp/bgp-mongo-bulk-load.py &
gobgp monitor global rib -j > /var/tmp/log/updates.json
# echo "BGP dump to MongoDB"
# gobgp monitor global rib -j | /var/tmp/bgp-mongo-bulk-load.py
