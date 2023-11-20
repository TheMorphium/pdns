#!/usr/bin/env python2

import dns
import dns.edns
import dns.flags
import dns.message
import dns.query

class CookiesOption(dns.edns.Option):
    """Implementation of draft-ietf-dnsop-cookies-09.
    """

    def __init__(self, client, server):
        super(CookiesOption, self).__init__(10)

        if len(client) != 8:
            raise Exception('invalid client cookie length')

        if server is not None and len(server) != 0 and (len(server) < 8 or len(server) > 32):
            raise Exception('invalid server cookie length')

        self.client = client
        self.server = server

    def to_wire(self, file=None):
        """Create EDNS packet as defined in draft-ietf-dnsop-cookies-09."""

        if self.server and len(self.server) > 0:
            data = self.client + self.server
        else:
            data = self.client

        if file:
            file.write(data)
        else:
            return data

    def from_wire(self, otype, wire, current, olen):
        """Read EDNS packet as defined in draft-ietf-dnsop-cookies-09.

        Returns:
            An instance of CookiesOption based on the EDNS packet
        """

        data = wire[current:current + olen]
        if len(data) != 8 and (len(data) < 16 or len(data) > 40):
            raise Exception('Invalid EDNS Cookies option')

        client = data[:8]
        server = data[8:] if len(data) > 8 else None
        return self(client, server)

    from_wire = classmethod(from_wire)

    # needed in 2.0.0
    @classmethod
    def from_wire_parser(cls, otype, parser):
        data = parser.get_remaining()

        if len(data) != 8 and (len(data) < 16 or len(data) > 40):
            raise Exception('Invalid EDNS Cookies option')

        client = data[:8]
        server = data[8:] if len(data) > 8 else None
        return cls(client, server)

    def __repr__(self):
        return f'{self.__class__.__name__}({self.client}, {self.server})'

    def to_text(self):
        return self.__repr__()

    def __eq__(self, other):
        if not isinstance(other, CookiesOption):
            return False
        return False if self.client != other.client else self.server == other.server

    def __ne__(self, other):
        return not self.__eq__(other)


dns.edns._type_to_class[0x000A] = CookiesOption

dns.rcode.BADCOOKIE = 23
