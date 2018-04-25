## Production
gobgp monitor global rib -j | /var/tmp/gobgp_to_mongo.py
##
## Dev Test
# cat /var/tmp/log/full_data.log | /var/tmp/gobgp_to_mongo.py
