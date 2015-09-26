
from twisted.internet import reactor, interfaces
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implementer
from twisted.plugin import IPlugin
from twisted.internet import error

from txsocksx.client import SOCKS5ClientEndpoint

from foolscap.ipb import IConnectionHintHandler, InvalidHintError


DOTTED_QUAD_RESTR=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
DNS_NAME_RESTR=r"[A-Za-z.0-9\-]+"
TOR_HINT_RE=re.compile(r"^(tcp|tor):(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                            DNS_NAME_RESTR))

@implementer(IConnectionHintHandler)
class TorClient():
    def __init__(self, socksHost, socksPort):
        self.tcpSocksEndpoint = TCP4Endpoint(reactor, socksHostname, socksPort)
        self.socksUsername = socksUsername
        self.socksPassword = socksPassword

    def hint_to_endpoint(self, hint, reactor):
        mo = TOR_HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized Tor hint")
        host, port = mo.group(1), int(mo.group(2))
        return SOCKS5ClientEndpoint(host, port, self.tcpSocksEndpoint), host
