from asn import ASN
import constants as C
import ipaddress
import time


class Prefix:
    """docstring for [object Object]."""
    ipv4_prefix_count = 0
    ipv6_prefix_count = 0
    prefix_dict = {}

    def __init__(self, args):
        self.prefix = args[C.PREFIX]
        self.origin = args[C.ORIGIN]
        self.nexthop = args[C.NEXT_HOP]
        self.as_path = args[C.AS_PATH]
        self.previous_as_paths = []
        self.next_hop_asn = self.as_path
        self.origin_as = self.as_path
        self.med = args[C.MULTI_EXIT_DISC]
        self.local_pref = args[C.LOCAL_PREF]
        self.withdrawal = args[C.WITHDRAWAL]
        self.age = args[C.AGE]
        self.communities = args[C.COMMUNITY]
        self.ip_version = ipaddress.ip_address(self.prefix.split('/', 1)[0]).version
        if self.ip_version == 4:
            Prefix.ipv4_prefix_count += 1
        if self.ip_version == 6:
            Prefix.ipv6_prefix_count += 1
        if self.prefix not in Prefix.prefix_dict:
            Prefix.prefix_dict[self.prefix] = self
        else:
            prefix_obj = Prefix.prefix_dict.get(self.prefix)
            if len(prefix_obj.previous_as_paths) > 0:
                if self.as_path != prefix_obj.previous_as_paths[0][0]:
                    prefix_obj.previous_as_paths.append((self.as_path, self.age))
        if not self.withdrawal and self.prefix not in self.origin_as.prefixes:
            C.logging.debug(self.origin_as.asn)
            C.logging.debug("ADD: " + self.prefix)
            self.origin_as.prefixes[self.prefix] = self
            self.previous_as_paths.append((self.as_path, self.age))
        if self.withdrawal and self.prefix in self.origin_as.prefixes:
            C.logging.debug(self.origin_as.asn)
            C.logging.debug("DEL: " + self.prefix)
            self.previous_as_paths.append((self.as_path, time.time()))
            del self.origin_as.prefixes[self.prefix]

    @property
    def as_path(self):
        return self._as_path

    @as_path.setter
    def as_path(self, as_path):
        if as_path == []:
            self._as_path = [C._DEFAULT_ASN]
        else:
            self._as_path = as_path

    @property
    def communities(self):
        return self._communities

    @communities.setter
    def communities(self, communities_list):
        try:
            temp = []
            for number in communities_list:
                temp.append(str(int(bin(number)[:-16], 2)) + ":" +
                            str(int(bin(number)[-16:], 2)))
            self._communities = temp
        except Exception:
            self._communities = None

    @property
    def next_hop_asn(self):
        return self._next_hop_asn

    @next_hop_asn.setter
    def next_hop_asn(self, as_path):
        try:
            self._next_hop_asn = as_path[0]
        except Exception:
            self._next_hop_asn = None

    @property
    def origin_as(self):
        return self._origin_as

    @origin_as.setter
    def origin_as(self, as_path):
        try:
            if as_path[-1] not in ASN.asn_dict:
                self._origin_as = ASN(as_path[-1])
            else:
                self._origin_as = ASN.asn_dict.get(as_path[-1])
        except Exception:
            self._origin_as = None

    @property
    def timestamp(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.age))
