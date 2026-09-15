package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Headers a reverse proxy uses to name the client it forwarded for.
const (
	forwardedForHeader = "X-Forwarded-For"
	realIPHeader       = "X-Real-IP"
)

// clientAddress returns the address a request is counted against.
//
// A forwarding header is only believed when the connection itself came from a
// configured proxy. Anyone can send one, so believing it unconditionally would
// let a single client present a new identity per request and never be limited.
//
// The forwarded chain is read from its trusted end. A proxy appends the peer it
// saw, so the rightmost entries are the ones the configured proxies wrote and
// anything a client sent itself sits to their left. A chain that is present but
// cannot be read in full falls back to the peer, and never to X-Real-IP, which
// the same client could have sent.
//
// The address is returned as text and is only ever used as input to a keyed
// hash; it is not stored or logged.
func (s *Server) clientAddress(request *http.Request) string {
	peer := peerAddress(request.RemoteAddr)

	if !s.trustsPeer(peer) {
		return peer.String()
	}

	if fields := request.Header.Values(forwardedForHeader); len(fields) > 0 {
		if client, readable := s.forwardedClient(fields); readable {
			return client.String()
		}

		return peer.String()
	}

	named := strings.TrimSpace(request.Header.Get(realIPHeader))
	if address, err := netip.ParseAddr(named); err == nil {
		return address.Unmap().String()
	}

	return peer.String()
}

func (s *Server) trustsPeer(peer netip.Addr) bool {
	if !peer.IsValid() {
		return false
	}

	for _, trusted := range s.config.TrustedProxies {
		if trusted.Contains(peer) {
			return true
		}
	}

	return false
}

// forwardedClient reads the client out of every X-Forwarded-For field, taken
// in arrival order as one comma-delimited chain.
//
// Every element must be an address. Walking from the right, each trusted hop is
// skipped and the nearest untrusted address is the client; a chain made only of
// trusted hops names its leftmost entry, which is what the first proxy saw.
func (s *Server) forwardedClient(fields []string) (netip.Addr, bool) {
	var chain []netip.Addr

	for _, field := range fields {
		for _, element := range strings.Split(field, ",") {
			address, err := netip.ParseAddr(strings.TrimSpace(element))
			if err != nil {
				return netip.Addr{}, false
			}

			chain = append(chain, address.Unmap())
		}
	}

	if len(chain) == 0 {
		return netip.Addr{}, false
	}

	for index := len(chain) - 1; index >= 0; index-- {
		if !s.trustsPeer(chain[index]) {
			return chain[index], true
		}
	}

	return chain[0], true
}

func peerAddress(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}

	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}

	return address.Unmap()
}
