package xip

// White-box tests for the unexported whitelist matching logic. They live in
// `package xip` (not `xip_test`) so they can call x.allowedByWhitelist directly.

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

func TestAllowedByWhitelist(t *testing.T) {
	x := &Xip{WhitelistCIDRs: []net.IPNet{
		mustCIDR("203.0.113.0/24"),     // a customer IPv4 block
		mustCIDR("2001:db8:abcd::/48"), // a customer IPv6 block
	}}

	cases := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"in-prefix IPv4 resolves", "203-0-113-5.example.com.", true},
		{"out-of-prefix IPv4 rejected", "8-8-8-8.example.com.", false},
		{"in-prefix IPv6 resolves", "2001-db8-abcd--1.example.com.", true},
		{"out-of-prefix IPv6 rejected", "2001-db8-ffff--1.example.com.", false},
		{"non-IP-encoding name passes through", "not-an-ip.example.com.", true},
	}
	for _, tc := range cases {
		if got := x.allowedByWhitelist(tc.hostname); got != tc.want {
			t.Errorf("%s: allowedByWhitelist(%q) = %v, want %v", tc.name, tc.hostname, got, tc.want)
		}
	}

	// Feature off: an empty whitelist must allow everything (preserves default behavior).
	xOff := &Xip{}
	if !xOff.allowedByWhitelist("8-8-8-8.example.com.") {
		t.Errorf("empty whitelist should allow all, but 8.8.8.8 was rejected")
	}

	// Operator-defined records (Customizations) are exempt even when their IP is
	// outside every customer prefix (8.8.8.8 is not in 203.0.113.0/24).
	const customName = "ns-whitelist-test.example.com."
	Customizations[customName] = DomainCustomization{
		A: []dnsmessage.AResource{{A: [4]byte{8, 8, 8, 8}}},
	}
	defer delete(Customizations, customName)
	if !x.allowedByWhitelist(customName) {
		t.Errorf("Customizations entry %q should be exempt from the whitelist", customName)
	}
}

func TestDelegateLabelTarget(t *testing.T) {
	x := &Xip{DelegateLabels: []string{"zone", "vm"}}

	cases := []struct {
		name string
		fqdn string
		want string
	}{
		{"apex match", "zone.1-2-3-4.example.com.", "1-2-3-4.example.com."},
		{"nested prefix", "anything.zone.1-2-3-4.example.com.", "1-2-3-4.example.com."},
		{"deeply nested prefix", "a.b.c.zone.1-2-3-4.example.com.", "1-2-3-4.example.com."},
		{"second label works too", "anything.vm.1-2-3-4.example.com.", "1-2-3-4.example.com."},
		{"leftmost label wins", "a.zone.b.zone.1-2-3-4.example.com.", "b.zone.1-2-3-4.example.com."},
		{"leftmost wins across different labels", "a.vm.b.zone.1-2-3-4.example.com.", "b.zone.1-2-3-4.example.com."},
		{"whole-label only: myzone must not match", "anything.myzone.1-2-3-4.example.com.", ""},
		{"whole-label only: myvm must not match", "anything.myvm.1-2-3-4.example.com.", ""},
		{"case-insensitive", "Anything.ZONE.1-2-3-4.Example.Com.", "1-2-3-4.example.com."},
		{"IPv6 target", "x.vm.2001-db8-abcd--1.example.com.", "2001-db8-abcd--1.example.com."},
		{"target without an embedded IP", "x.zone.foo.example.com.", ""},
		{"no label present", "1-2-3-4.example.com.", ""},
	}
	for _, tc := range cases {
		if got := x.delegateLabelTarget(tc.fqdn); got != tc.want {
			t.Errorf("%s: delegateLabelTarget(%q) = %q, want %q", tc.name, tc.fqdn, got, tc.want)
		}
	}

	// Feature off: no labels configured never delegates.
	xOff := &Xip{}
	if got := xOff.delegateLabelTarget("x.zone.1-2-3-4.example.com."); got != "" {
		t.Errorf("empty DelegateLabels should disable delegation, got %q", got)
	}
}
