package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type Scanner struct {
	// сколько одновременных воркеров будет кидать dial на порты
	concurrency int
	// таймаут установления TCP-соединения для каждого порта
	connectTimeout time.Duration
}

const (
	maxChannelCap       = 4096
	resultsBufPerWorker = 2
	jobsBufPerWorker    = 8
)

func channelCap(concurrency, perWorker int) int {
	size := concurrency * perWorker
	if size > maxChannelCap {
		return maxChannelCap
	}
	if size < 1 {
		return 1
	}
	return size
}

func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:    100,
		connectTimeout: 500 * time.Millisecond,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(s)
	}

	if s.concurrency <= 0 {
		return nil, ErrInvalidConcurrency
	}
	if s.connectTimeout <= 0 {
		return nil, ErrInvalidTimeout
	}
	return s, nil
}

type hostTarget struct {
	host string
	ip   net.IP
}

func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if len(hosts) == 0 {
		return closedResults(), ErrEmptyHosts
	}

	portList, err := ports.validateAndExpand()
	if err != nil {
		return closedResults(), err
	}
	if len(portList) == 0 {
		return closedResults(), nil
	}

	targets, err := resolveTargets(ctx, hosts)
	if err != nil {
		return closedResults(), err
	}
	if len(targets) == 0 {
		return closedResults(), ErrNoHostsResolved
	}

	results := make(chan Result, channelCap(s.concurrency, resultsBufPerWorker))
	jobs := make(chan job, channelCap(s.concurrency, jobsBufPerWorker))

	var wg sync.WaitGroup
	// стартуем ровно concurrency воркеров
	wg.Add(s.concurrency)
	for i := 0; i < s.concurrency; i++ {
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	go func() {
		defer func() {
			close(jobs)
			wg.Wait()
			close(results)
		}()

		for _, target := range targets {
			for _, port := range portList {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{target: target, port: port}:
				}
			}
		}
	}()

	return results, nil
}

type job struct {
	target hostTarget
	port   uint16
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan job, results chan<- Result) {
	for {
		select {
		case <-ctx.Done():
			return
		case current, ok := <-jobs:
			if !ok {
				return
			}
			res := s.checkOne(ctx, current.target, current.port)
			select {
			case <-ctx.Done():
				return
			case results <- res:
			}
		}
	}
}

func (s *Scanner) checkOne(ctx context.Context, target hostTarget, port uint16) Result {
	start := time.Now()

	dialer := &net.Dialer{
		Timeout:   s.connectTimeout,
		KeepAlive: 0,
	}

	addr := net.JoinHostPort(target.ip.String(), fmt.Sprintf("%d", port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	duration := time.Since(start)

	if err == nil && conn != nil {
		_ = conn.Close()
		return Result{
			Host:     target.host,
			IP:       target.ip,
			Port:     port,
			State:    Open,
			Duration: duration,
			Err:      nil,
		}
	}

	state := classifyDialError(ctx, err)
	return Result{
		Host:     target.host,
		IP:       target.ip,
		Port:     port,
		State:    state,
		Duration: duration,
		Err:      err,
	}
}

func classifyDialError(ctx context.Context, err error) State {
	if err == nil {
		return Error
	}

	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return Canceled
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Canceled
		}
	}

	if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}

	if st, ok := classifySyscall(err); ok {
		return st
	}

	return Error
}

func closedResults() <-chan Result {
	ch := make(chan Result)
	close(ch)
	return ch
}
