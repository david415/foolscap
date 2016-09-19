import os, re
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from twisted.internet.endpoints import clientFromString
import ipaddress
from .. import observer

from zope.interface import implementer
from ..ipb import IConnectionHintHandler, InvalidHintError
from ..util import allocate_tcp_port
import txtorcon
from .tcp import DOTTED_QUAD_RESTR, DNS_NAME_RESTR

def is_non_public_numeric_address(host):
    # for numeric hostnames, skip RFC1918 addresses, since no Tor exit
    # node will be able to reach those. Likewise ignore IPv6 addresses.
    try:
        a = ipaddress.ip_address(host.decode("ascii")) # wants unicode
    except ValueError:
        return False # non-numeric, let Tor try it
    if a.version != 4:
        return True # IPv6 gets ignored
    if (a.is_loopback or a.is_multicast or a.is_private or a.is_reserved
        or a.is_unspecified):
        return True # too weird, don't connect
    return False

HINT_RE = re.compile(r"^[^:]*:(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                      DNS_NAME_RESTR))

@implementer(IConnectionHintHandler)
class _Common:
    # subclasses must define self._connect(reactor), which fires with the
    # socks Endpoint that TorClientEndpoint can use

    def __init__(self):
        self._connected = False
        self._when_connected = observer.OneShotObserverList()

    def _maybe_connect(self, reactor):
        if not self._connected:
            self._connected = True
            d = self._connect(reactor)
            d.addBoth(self._when_connected.fire)
        return self._when_connected.whenFired()

    @inlineCallbacks
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP/Tor hint")
        host, portnum = mo.group(1), int(mo.group(2))
        if is_non_public_numeric_address(host):
            raise InvalidHintError("ignoring non-Tor-able ipaddr %s" % host)
        socks_endpoint = yield self._maybe_connect(reactor)
        # txsocksx doesn't like unicode: it concatenates some binary protocol
        # bytes with the hostname when talking to the SOCKS server, so the
        # py2 automatic unicode promotion blows up
        host = host.encode("ascii")
        ep = txtorcon.TorClientEndpoint(host, portnum,
                                        socks_endpoint=socks_endpoint)
        returnValue( (ep, host) )


# note: TorClientEndpoint imports 'reactor' itself, doesn't provide override.
# This will be fixed in txtorcon 1.0

class _SocksTor(_Common):
    def __init__(self, socks_endpoint=None):
        _Common.__init__(self)
        self._socks_endpoint = socks_endpoint
        # socks_endpoint=None means to use defaults: TCP to 127.0.0.1 with
        # 9050, then 9150
    def _connect(self, reactor):
        return succeed(self._socks_endpoint)

def default_socks():
    return _SocksTor()

def socks_endpoint(tor_socks_endpoint):
    assert IStreamClientEndpoint.providedBy(tor_socks_endpoint)
    return _SocksTor(tor_socks_endpoint)

@implementer(IConnectionHintHandler)
class _ConnectedTor(_Common):
    def __init__(self, tor_provider):
        _Common.__init__(self)
        self._tor_provider= tor_provider

    @inlineCallbacks
    def _connect(self, reactor):
        tproto = yield self.tor_provider.get_control_protocol()
        config = yield txtorcon.TorConfig.from_protocol(tproto)
        ports = list(config.SocksPort)
        # I've seen "9050", and "unix:/var/run/tor/socks WorldWritable"
        for port in ports:
            pieces = port.split()
            p = pieces[0]
            if p == txtorcon.DEFAULT_VALUE:
                p = "9050"
            try:
                portnum = int(p)
                socks_desc = "tcp:127.0.0.1:%d" % portnum
                self._socks_desc = socks_desc # stash for tests
                socks_endpoint = clientFromString(reactor, socks_desc)
                returnValue(socks_endpoint)
            except ValueError:
                pass
        raise ValueError("could not use config.SocksPort: %r" % (ports,))

def handler_from_tor_provider(tor_provider):
    """Return a handler which uses the given TorProvider's control port
    to get an SOCKS port when needed.
    """
    return _ConnectedTor(tor_provider)
