package portscan

import "time"

type Option func(*Scanner)

func WithConcurrency(n int) Option {
	return func(s *Scanner) {
		s.concurrency = n
	}
}

func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) {
		s.connectTimeout = d
	}
}
