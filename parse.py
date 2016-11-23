#! /usr/bin/env python3

import json

def myprint2(d):
  for k, v in d.items():
    if isinstance(v, dict):
        myprint2(v)
    else:
        if k == 'attrs':
            print("{0} : {1}".format(k, v))
            print()
      
def myprint(d):
  for k, v in d.items():
    if isinstance(v, dict):
      myprint(v)
    else:
      print("{0} : {1}".format(k, v))
      
      
def traverse(obj):
    if isinstance(obj, dict):
        return {k: traverse(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [traverse(elem) for elem in obj]
    else:
        return obj  # no container, just values (str, int, float)
        

def locateByName(e,name):
    if e.get('name',None) == name:
        return e

    for child in e.get('children',[]):
        result = locateByName(child,name)
        if result is not None:
            return result

    return None

with open('log/log.json', 'r') as f:
     data = json.load(f)

#myprint2(data)

for k, v in data.items():
    print("Prefix: ", v[0]['nlri']['prefix'])
    #print("AS Path: ", v[0]['attrs'][1]['as_paths'][0]['asns'])
    for attribute in v[0]['attrs']:
        if attribute['type'] == 3:
            print("Next Hop: ", attribute['nexthop'])
        elif attribute['type'] == 2:
            try:
                print("AS Path: ", attribute['as_paths'][0]['asns'])
                print("Next Hop ASN: ", attribute['as_paths'][0]['asns'][0])
            except:
                print("AS Path: Local")
        elif attribute['type'] == 7:
            try:
                print("Origin ASN: ", attribute['as'])
            except:
                print("Origin ASN: None", None)
    #print("Origin ASN: ", v[0]['attrs'][2]['as'])
    print()
# 
#     # if v == "age":
#     #     print("age")
#     #print("{0}".format(k))
