from twisted.internet import reactor, interfaces
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implementer
from twisted.plugin import IPlugin
from twisted.internet import error

from txsocksx.client import SOCKS5ClientEndpoint

from foolscap.ipb import IConnectionHintHandler, InvalidHintError



@implementer(IConnectionHintHandler)
class TorClient:
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = NEW_STYLE_HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP hint")
        host, port = mo.group(1), int(mo.group(2))
        return TorClientEndpoint(host, port), host


@implementer(interfaces.IStreamClientEndpoint)
class TorClientEndpoint(object):
    """I am an endpoint class who attempts to establish a SOCKS5 connection
    with the system tor process. Either the user must pass a SOCKS port into my
    constructor OR I will attempt to guess the Tor SOCKS port by iterating over a list of ports
    that tor is likely to be listening on.
    :param host: The hostname to connect to.
    This of course can be a Tor Hidden Service onion address.
    :param port: The tcp port or Tor Hidden Service port.
    :param proxyEndpointGenerator: This is used for unit tests.
    :param socksPort: This optional argument lets the user specify which Tor SOCKS port should be used.
    """
    socks_ports_to_try = [9050, 9150]

    # XXX this should probably take a reactor as an argument as well instead of using the global reactor
    def __init__(self, host, port, proxyEndpointGenerator=DefaultTCP4EndpointGenerator, socksHostname=None, socksPort=None, socksUsername=None, socksPassword=None):
        if host is None or port is None:
            raise ValueError('host and port must be specified')

        self.host = host
        self.port = port
        self.proxyEndpointGenerator = proxyEndpointGenerator
        self.socksHostname = socksHostname
        self.socksPort = socksPort
        self.socksUsername = socksUsername
        self.socksPassword = socksPassword

        if self.socksPort is None:
            self.socksPortIter = iter(self.socks_ports_to_try)
            self.socksGuessingEnabled = True
        else:
            self.socksGuessingEnabled = False

    # XXX simplify by removing this connection retry logic?
    def connect(self, protocolfactory):
        self.protocolfactory = protocolfactory

        if self.socksGuessingEnabled:
            self.socksPort = self.socksPortIter.next()

        d = self._try_connect()
        return d

    def _try_connect(self):
        self.torSocksEndpoint = self.proxyEndpointGenerator(reactor, self.socksHostname, self.socksPort)

        if self.socksUsername is None or self.socksPassword is None:
            socks5ClientEndpoint = SOCKS5ClientEndpoint(self.host, self.port, self.torSocksEndpoint)
        else:
            socks5ClientEndpoint = SOCKS5ClientEndpoint(self.host, self.port, self.torSocksEndpoint,
                                                        methods={ 'login': (self.socksUsername, self.socksPassword) })


        d = socks5ClientEndpoint.connect(self.protocolfactory)
        if self.socksGuessingEnabled:
            d.addErrback(self._retry_socks_port)
        return d

    def _retry_socks_port(self, failure):
        failure.trap(error.ConnectError)
        try:
            self.socksPort = self.socksPortIter.next()
        except StopIteration:
            return failure
        d = self._try_connect()
        d.addErrback(self._retry_socks_port)
        return d
