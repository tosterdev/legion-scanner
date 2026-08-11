package portscan

import "errors"

var (
	ErrInvalidConcurrency = errors.New("concurrency must be > 0")
	ErrInvalidTimeout     = errors.New("connectTimeout must be > 0")
	ErrEmptyHosts         = errors.New("hosts must not be empty")
	ErrNoHostsResolved    = errors.New("no valid hosts resolved")
	ErrUnknownPortItem    = errors.New("unknown port item kind")
	ErrEmptyHost          = errors.New("empty host")
	ErrParseIPFailed      = errors.New("parse ip failed")
)
