package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/config"
)

// behindProxies is a service that believes forwarding headers from the given
// ranges and nothing else.
func behindProxies(t *testing.T, ranges ...string) *Server {
	t.Helper()

	prefixes := make([]netip.Prefix, 0, len(ranges))

	for _, cidr := range ranges {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("%q is not a range: %v", cidr, err)
		}

		prefixes = append(prefixes, prefix)
	}

	return &Server{config: config.Config{TrustedProxies: prefixes}}
}

// forwarded builds a request from a peer carrying the given header lines, each
// as its own field.
func forwarded(peer string, lines ...[2]string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, APIRoot+"/login", nil)
	request.RemoteAddr = peer

	for _, line := range lines {
		request.Header.Add(line[0], line[1])
	}

	return request
}

// The client a request is counted against is the one the configured proxies
// saw: a header from anywhere else is ignored, and anything a client put in
// front of what the proxy appended is ignored too.
func TestTheClientAddressIsReadFromTheTrustedEndOfTheChain(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		trusted []string
		request *http.Request
		want    string
	}{
		"an untrusted peer is itself, whatever it sends": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("198.51.100.5:4000",
				[2]string{"X-Forwarded-For", "203.0.113.9"},
				[2]string{"X-Real-IP", "203.0.113.10"},
			),
			want: "198.51.100.5",
		},
		"one trusted proxy names the client": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("10.1.2.3:4000", [2]string{"X-Forwarded-For", "203.0.113.9"}),
			want:    "203.0.113.9",
		},
		"a value the client sent is left of the one the proxy appended": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("10.1.2.3:4000", [2]string{"X-Forwarded-For", "198.51.100.7, 203.0.113.9"}),
			want:    "203.0.113.9",
		},
		"the same, with the proxy appending its own line": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("10.1.2.3:4000",
				[2]string{"X-Forwarded-For", "198.51.100.7"},
				[2]string{"X-Forwarded-For", "203.0.113.9"},
			),
			want: "203.0.113.9",
		},
		"several trusted proxies are walked past": {
			trusted: []string{"10.0.0.0/8", "172.16.0.0/12"},
			request: forwarded("10.1.2.3:4000",
				[2]string{"X-Forwarded-For", "198.51.100.7, 203.0.113.9, 172.16.0.4, 10.0.0.8"},
			),
			want: "203.0.113.9",
		},
		"a chain of only trusted hops names its first entry": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("10.1.2.3:4000", [2]string{"X-Forwarded-For", "10.0.0.7, 10.0.0.8"}),
			want:    "10.0.0.7",
		},
		"an IPv4-mapped address is the IPv4 address": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("[::ffff:10.1.2.3]:4000", [2]string{"X-Forwarded-For", "::ffff:203.0.113.9"}),
			want:    "203.0.113.9",
		},
		"an IPv6 client behind an IPv6 proxy": {
			trusted: []string{"fd00::/8"},
			request: forwarded("[fd00::1]:4000", [2]string{"X-Forwarded-For", "2001:db8::9"}),
			want:    "2001:db8::9",
		},
		"the loopback default trusts a sidecar": {
			trusted: []string{"127.0.0.1/32", "::1/128"},
			request: forwarded("127.0.0.1:4000", [2]string{"X-Forwarded-For", "203.0.113.9"}),
			want:    "203.0.113.9",
		},
		"X-Real-IP is used only when no chain was sent at all": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("10.1.2.3:4000", [2]string{"X-Real-IP", "203.0.113.9"}),
			want:    "203.0.113.9",
		},
		"a trusted peer sending nothing is itself": {
			trusted: []string{"10.0.0.0/8"},
			request: forwarded("10.1.2.3:4000"),
			want:    "10.1.2.3",
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := behindProxies(t, testCase.trusted...)

			if got := service.clientAddress(testCase.request); got != testCase.want {
				t.Errorf("clientAddress = %q, want %q", got, testCase.want)
			}
		})
	}
}

// A chain that is present but cannot be read in full is not read at all: the
// request is counted against the peer, and X-Real-IP, which the same client
// could have sent, is not consulted in its place.
func TestAnUnreadableChainFallsBackToThePeerAndNeverToXRealIP(t *testing.T) {
	t.Parallel()

	unreadable := map[string][]string{
		"an empty field":                {""},
		"a field of only whitespace":    {"   "},
		"an empty element":              {"203.0.113.9, , 10.0.0.8"},
		"a trailing comma":              {"203.0.113.9,"},
		"a host name":                   {"client.example.test"},
		"an address with a port":        {"203.0.113.9:4000"},
		"a malformed entry beside good": {"203.0.113.9, not-an-address"},
		"an empty later line":           {"203.0.113.9", ""},
		"a malformed later line":        {"203.0.113.9", "garbage"},
		"a bracketed IPv6 address":      {"[2001:db8::9]"},
	}

	for name, lines := range unreadable {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := behindProxies(t, "10.0.0.0/8")

			fields := [][2]string{{"X-Real-IP", "198.51.100.200"}}
			for _, line := range lines {
				fields = append(fields, [2]string{"X-Forwarded-For", line})
			}

			request := forwarded("10.1.2.3:4000", fields...)

			if got := service.clientAddress(request); got != "10.1.2.3" {
				t.Errorf("clientAddress = %q, want the peer", got)
			}
		})
	}
}

// A peer that is not an address at all is trusted by nobody and counted as
// what it is.
func TestAPeerThatIsNotAnAddressIsNotTrusted(t *testing.T) {
	t.Parallel()

	service := behindProxies(t, "0.0.0.0/0", "::/0")

	request := forwarded("not-an-address", [2]string{"X-Forwarded-For", "203.0.113.9"})

	if service.trustsPeer(peerAddress(request.RemoteAddr)) {
		t.Error("a peer with no address was trusted")
	}

	if got := service.clientAddress(request); got == "203.0.113.9" {
		t.Error("a forwarding header from a peer with no address was believed")
	}
}
