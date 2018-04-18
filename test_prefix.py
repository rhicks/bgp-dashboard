import unittest
import constants as C
import time
from prefix import Prefix

# Test Prefix object returns the prefix
prefix = "140.211.0.0/16"
origin = C.IGP
as_path = []
nexthop = "0.0.0.0"
med = 0
local_pref = 0
atomic_aggregate = None
aggregator = 0
communities = []
originator_id = "0.0.0.0"
cluster_list = "0.0.0.0"
withdrawal = False
age = 1524004385

testprefix = Prefix((prefix, origin, as_path, nexthop, med, local_pref, atomic_aggregate, aggregator, communities, originator_id, cluster_list, withdrawal, age))


class TestPrefix(unittest.TestCase):
    def test_prefix(self):
        self.assertEqual("140.211.0.0/16", testprefix.prefix)

    def test_nexthop(self):
        self.assertEqual("0.0.0.0", testprefix.nexthop)

    def test_asn(self):
        self.assertEqual(3701, testprefix.origin_as.asn)

    def test_asn_name(self):
        time.sleep(1)  # Wait x seconds for dns query thread to finish. Increase as needed
        self.assertEqual("NERONET - Network for Education and Research in Oregon (NERO)", testprefix.origin_as.name)

    def test_asn_prefixes(self):
        self.assertIn("140.211.0.0/16", testprefix.origin_as.prefixes)

    def test_previous_as_paths(self):
        Prefix((prefix, origin, [4201], nexthop, med, local_pref, atomic_aggregate, aggregator, communities, originator_id, cluster_list, withdrawal, 1524004386))
        self.assertIn(([3701], 1524004385), testprefix.previous_as_paths)
        self.assertIn(([4201], 1524004386), testprefix.previous_as_paths)
