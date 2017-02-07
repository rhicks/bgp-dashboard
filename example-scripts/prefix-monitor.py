#! /usr/bin/env python

import urllib
import json
import sys


def dict_diff(dict1, dict2):
    diffkeys = [k for k in dict1 if dict1[k] != dict2[k]]
    for k in diffkeys:
        print('{key}: {before_val} -> {new_val}'.format(key=str(k), before_val=dict1[k], new_val=dict2[k]))


def previous_data(prefix):
    try:
        with open('{prefix}.json'.format(prefix=prefix), 'r') as f:
            data = json.load(f)
        return data
    except:
        return None


def get_data_from_url(prefix):
    try:
        url = "http://bgp.nero.net/bgp/api/v1.0/ip/{prefix}".format(prefix=prefix)
        response = urllib.urlopen(url)
        data = json.loads(response.read())
        return data
    except Exception, e:
        print(e)
        return None


def save_data_for_next_compare(prefix, data):
    try:
        with open('{prefix}.json'.format(prefix=prefix), 'w') as outfile:
            json.dump(data, outfile)
    except Exception, e:
        print(e)
        return None


def main():
    if len(sys.argv) < 2:
        print('usage: prefix-monitor.py "ip_address"')
    else:
        prefix = sys.argv[1]
        old_json = previous_data(prefix)
        new_json = get_data_from_url(prefix)
        if old_json is None:
            save_data_for_next_compare(prefix, new_json)
            print('##########################')
            print('### New prefix monitor ###')
            print('##########################')
            print(json.dumps(new_json, indent=2))
        else:
            dict_diff(dict(old_json), dict(new_json))
            save_data_for_next_compare(prefix, new_json)


if __name__ == "__main__":
    sys.exit(main())
