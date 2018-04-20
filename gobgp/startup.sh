# gobgp monitor global rib -j | /var/tmp/bgp-mongo-bulk-load.py
# gobgp monitor global rib -j > /var/tmp/log/new.log
cat /var/tmp/log/new.log | /var/tmp/bgp-mongo-bulk-load.py
