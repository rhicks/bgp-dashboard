import constants as C
import dns.resolver
import threading
# from multiprocessing.pool import ThreadPool
# pool = ThreadPool(processes=1)


def asn_name_query(self, as_number):
    """Given an *asn*, return the name."""
    # print(as_number)
    if as_number is None:
        as_number = C._DEFAULT_ASN
    if 64496 <= as_number <= 64511:
        return('RFC5398 - Private Use ASN')
    if 64512 <= as_number <= 65535 or 4200000000 <= as_number <= 4294967295:
        return('RFC6996 - Private Use ASN')
    try:
        query = 'as{number}.asn.cymru.com'.format(number=str(as_number))
        resolver = dns.resolver.Resolver()
        answers = resolver.query(query, 'TXT')
        for rdata in answers:
            self._name = str(rdata).split('|')[-1].split(',', 2)[0].strip()
    except Exception:
        self._name = '(DNS Error)'


class ASN:
    asn_dict = {}

    def __init__(self, as_number):
        self.asn = as_number
        self.prefixes = {}
        self.name = self.asn
        ASN.asn_dict[self.asn] = self

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, as_number):
        try:
            threading.Thread(target=asn_name_query, args=(self, as_number)).start()
            # self._name = asn_name_query(asn)
            # print(self.name)
            # self._name = "BYPASS"
            # async_result = pool.apply_async(asn_name_query, (self, asn))
            # self._name = async_result.get()

        except Exception as err:
            print(err)
            self._name = None
