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
// The address is returned as text and is only ever used as input to a keyed
// hash; it is not stored or logged.
func (s *Server) clientAddress(request *http.Request) string {
	peer := peerAddress(request.RemoteAddr)

	if !s.trustsPeer(peer) {
		return peer.String()
	}

	if forwarded, found := firstForwardedAddress(request.Header.Get(forwardedForHeader)); found {
		return forwarded.String()
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

// firstForwardedAddress reads the client the proxy named. The list grows by
// appending, so the client is the first entry, and anything a client sent
// itself is behind it.
func firstForwardedAddress(header string) (netip.Addr, bool) {
	first, _, _ := strings.Cut(header, ",")

	address, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return netip.Addr{}, false
	}

	return address.Unmap(), true
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
