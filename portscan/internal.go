package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
)

type resolveErrorKind int

const (
	resolveErrInvalidHost resolveErrorKind = iota
	resolveErrUnresolvableDNS
)

type ResolveError struct {
	Kind  resolveErrorKind
	Host  string
	Cause error
}

func (e ResolveError) Error() string {
	switch e.Kind {
	case resolveErrInvalidHost:
		if e.Cause != nil {
			return fmt.Sprintf("invalid host: %q: %v", e.Host, e.Cause)
		}
		return fmt.Sprintf("invalid host: %q", e.Host)
	case resolveErrUnresolvableDNS:
		if e.Cause != nil {
			return fmt.Sprintf("unresolvable DNS: %q: %v", e.Host, e.Cause)
		}
		return fmt.Sprintf("unresolvable DNS: %q", e.Host)
	default:
		return fmt.Sprintf("host resolve error: %q", e.Host)
	}
}

func (e ResolveError) Unwrap() error { return e.Cause }

func resolveTargets(ctx context.Context, hosts []string) ([]hostTarget, error) {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]hostTarget, 0, len(hosts))
	dnsHosts := make([]string, 0)

	for _, rawHost := range hosts {
		host := strings.TrimSpace(rawHost)
		if host == "" {
			return nil, ResolveError{Kind: resolveErrInvalidHost, Host: host, Cause: ErrEmptyHost}
		}

		ip := net.ParseIP(host)
		var key string
		if ip != nil {
			key = ip.String()
		} else {
			if looksLikeAddress(host) {
				return nil, ResolveError{Kind: resolveErrInvalidHost, Host: host, Cause: ErrParseIPFailed}
			}
			key = strings.ToLower(host)
		}

		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if ip != nil {
			out = append(out, hostTarget{host: host, ip: ip})
			continue
		}
		dnsHosts = append(dnsHosts, host)
	}

	if len(dnsHosts) == 0 {
		return out, nil
	}

	resolved, err := lookupDNSParallel(ctx, dnsHosts)
	if err != nil {
		return nil, err
	}
	out = append(out, resolved...)
	return out, nil
}

func lookupDNSParallel(ctx context.Context, dnsHosts []string) ([]hostTarget, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		out      = make([]hostTarget, 0, len(dnsHosts))
	)

	setErr := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr != nil {
			return
		}
		firstErr = err
		cancel()
	}

	for _, host := range dnsHosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()

			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					setErr(fmt.Errorf("dns lookup %q: %w", host, err))
					return
				}

				setErr(ResolveError{
					Kind:  resolveErrUnresolvableDNS,
					Host:  host,
					Cause: err,
				})
				return
			}

			mu.Lock()
			if firstErr == nil {
				for _, ipAddr := range ips {
					out = append(out, hostTarget{host: host, ip: ipAddr.IP})
				}
			}
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func looksLikeAddress(host string) bool {
	for _, r := range host {
		if (r >= '0' && r <= '9') || r == '.' || r == ':' || r == '[' || r == ']' {
			continue
		}
		return false
	}
	return true
}

func classifySyscall(err error) (State, bool) {
	if err == nil {
		return Error, false
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return classifyErrno(errno)
	}

	var se *os.SyscallError
	if errors.As(err, &se) {
		if errno, ok := se.Err.(syscall.Errno); ok {
			return classifyErrno(errno)
		}
	}

	return Error, false
}

func classifyErrno(errno syscall.Errno) (State, bool) {
	// Winsock-коды (syscall.Errno).
	const (
		wsaECONNREFUSED = 10061
		wsaENETUNREACH  = 10051
		wsaEHOSTUNREACH = 10065
		wsaENETDOWN     = 10050
	)

	switch errno {
	case syscall.ECONNREFUSED, wsaECONNREFUSED:
		return Closed, true
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN,
		wsaENETUNREACH, wsaEHOSTUNREACH, wsaENETDOWN:
		return Unreachable, true
	}

	return Error, false
}
