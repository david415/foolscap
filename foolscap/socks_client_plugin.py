
from twisted.internet import reactor, interfaces
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implementer
from twisted.plugin import IPlugin
from twisted.internet import error

from txsocksx.client import SOCKS5ClientEndpoint

from foolscap.ipb import IConnectionHintHandler, InvalidHintError



@implementer(IConnectionHintHandler)
class SocksClient:
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = NEW_STYLE_HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP hint")
        host, port = mo.group(1), int(mo.group(2))
        return SocksClientEndpoint(reactor, host, port), host


@implementer(interfaces.IStreamClientEndpoint)
class SocksClientEndpoint(object):
    """I am an endpoint class who attempts to establish a SOCKS5 connection.
    :param host: The destination hostname.
    :param port: The destination port.
    :param proxyEndpointGenerator: This is used for unit tests.
    :param socksHostname: SOCKS hostname.
    :param socksPort: SOCKS port.
    """

    # XXX this should probably take a reactor as an argument as well instead of using the global reactor
    def __init__(self, reactor, host, port, proxyEndpointGenerator=DefaultTCP4EndpointGenerator, socksHostname=None, socksPort=None, socksUsername=None, socksPassword=None):
        if host is None or port is None:
            raise ValueError('host and port must be specified')

        self.reactor = reactor
        self.host = host
        self.port = port
        self.proxyEndpointGenerator = proxyEndpointGenerator
        self.socksHostname = socksHostname
        self.socksPort = socksPort
        self.socksUsername = socksUsername
        self.socksPassword = socksPassword

    def connect(self, protocolfactory):
        tcpSocksEndpoint = self.proxyEndpointGenerator(self.reactor, self.socksHostname, self.socksPort)

        if self.socksUsername is None or self.socksPassword is None:
            socks5ClientEndpoint = SOCKS5ClientEndpoint(self.host, self.port, tcpSocksEndpoint)
        else:
            socks5ClientEndpoint = SOCKS5ClientEndpoint(self.host, self.port, tcpSocksEndpoint,
                                                        methods={ 'login': (self.socksUsername, self.socksPassword) })

        return socks5ClientEndpoint.connect(protocolfactory)
