package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

type resolveErrorKind uint8

const (
	resolveErrInvalidHost resolveErrorKind = iota
	resolveErrUnresolvableDNS
)

type ResolveError struct {
	Kind  resolveErrorKind
	Host  string
	Cause error
}

func (e *ResolveError) Error() string {
	switch e.Kind {
	case resolveErrInvalidHost:
		return fmt.Sprintf("invalid host: %q", e.Host)
	case resolveErrUnresolvableDNS:
		return fmt.Sprintf("unresolvable DNS: %q", e.Host)
	default:
		return fmt.Sprintf("host resolve error: %q", e.Host)
	}
}

func (e *ResolveError) Unwrap() error { return e.Cause }

func resolveTargets(ctx context.Context, hosts []string) ([]hostTarget, error) {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]hostTarget, 0, len(hosts))

	for _, raw := range hosts {
		h := strings.TrimSpace(raw)
		if h == "" {
			return nil, &ResolveError{Kind: resolveErrInvalidHost, Host: raw, Cause: errors.New("empty host")}
		}

		ip := net.ParseIP(h)
		var key string
		if ip != nil {
			key = "ip:" + ip.String()
		} else {
			key = "dns:" + strings.ToLower(h)
			if looksLikeAddress(h) {
				return nil, &ResolveError{Kind: resolveErrInvalidHost, Host: h, Cause: errors.New("parse ip failed")}
			}
		}

		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if ip != nil {
			out = append(out, hostTarget{host: h, ip: ip})
			continue
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, &ResolveError{Kind: resolveErrUnresolvableDNS, Host: h, Cause: err}
		}
		for _, ipAddr := range ips {
			out = append(out, hostTarget{host: h, ip: ipAddr.IP})
		}
	}

	return out, nil
}

func looksLikeAddress(s string) bool {
	for _, r := range s {
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
