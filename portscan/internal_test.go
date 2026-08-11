package portscan

import (
	"context"
	"errors"
	"net"
	"testing"
)

func assertResolveError(t *testing.T, err error, kind resolveErrorKind, host string) {
	t.Helper()

	var re *ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("expected *ResolveError, got %v", err)
	}
	if re.Kind != kind {
		t.Fatalf("expected kind %v, got %v", kind, re.Kind)
	}
	if re.Host != host {
		t.Fatalf("expected host %q, got %q", host, re.Host)
	}
}

func TestResolveTargets_emptyHost(t *testing.T) {
	ctx := context.Background()

	for _, host := range []string{"", "   "} {
		t.Run(host, func(t *testing.T) {
			_, err := resolveTargets(ctx, []string{host})
			assertResolveError(t, err, resolveErrInvalidHost, host)
		})
	}
}

func TestResolveTargets_invalidAddress(t *testing.T) {
	ctx := context.Background()

	for _, host := range []string{"999.999.999.999", "256.1.1.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			_, err := resolveTargets(ctx, []string{host})
			assertResolveError(t, err, resolveErrInvalidHost, host)
		})
	}
}

func TestResolveTargets_unresolvableDNS(t *testing.T) {
	ctx := context.Background()
	host := "legion-scanner-no-such-host.invalid"

	_, err := resolveTargets(ctx, []string{host})
	assertResolveError(t, err, resolveErrUnresolvableDNS, host)
}

func TestResolveTargets_duplicates(t *testing.T) {
	ctx := context.Background()

	t.Run("duplicate ipv4", func(t *testing.T) {
		targets, err := resolveTargets(ctx, []string{"127.0.0.1", "127.0.0.1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(targets))
		}
	})

	t.Run("duplicate dns case insensitive", func(t *testing.T) {
		targets, err := resolveTargets(ctx, []string{"LocalHost", "localhost"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(targets) < 1 {
			t.Fatalf("expected at least 1 target, got %d", len(targets))
		}
	})
}

func TestResolveTargets_multipleIPsFromDNS(t *testing.T) {
	ctx := context.Background()

	targets, err := resolveTargets(ctx, []string{"localhost"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) < 1 {
		t.Fatalf("expected at least 1 target, got %d", len(targets))
	}

	seenIPs := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.host != "localhost" {
			t.Fatalf("expected host localhost, got %q", target.host)
		}
		if target.ip == nil {
			t.Fatal("expected non-nil ip")
		}
		seenIPs[target.ip.String()] = struct{}{}
	}
	if len(seenIPs) != len(targets) {
		t.Fatalf("expected unique IPs, got %d targets and %d unique ips", len(targets), len(seenIPs))
	}
}

func TestResolveTargets_ipv4AndIPv6(t *testing.T) {
	ctx := context.Background()

	t.Run("ipv4", func(t *testing.T) {
		targets, err := resolveTargets(ctx, []string{"192.168.1.10"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(targets))
		}
		if targets[0].ip.To4() == nil {
			t.Fatalf("expected ipv4, got %s", targets[0].ip)
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		targets, err := resolveTargets(ctx, []string{"::1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(targets))
		}
		if targets[0].ip.To4() != nil {
			t.Fatalf("expected ipv6, got %s", targets[0].ip)
		}
	})
}

func TestResolveTargets_ipv4LiteralUsesCanonicalIP(t *testing.T) {
	ctx := context.Background()

	targets, err := resolveTargets(ctx, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if !targets[0].ip.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("unexpected ip: %s", targets[0].ip)
	}
}
