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
		return nil, fmt.Errorf("concurrency must be > 0")
	}
	if s.connectTimeout <= 0 {
		return nil, fmt.Errorf("connectTimeout must be > 0")
	}
	return s, nil
}

type hostTarget struct {
	host string
	ip   net.IP
}

func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if len(hosts) == 0 {
		return closedResults(), fmt.Errorf("hosts must not be empty")
	}

	if s == nil {
		return closedResults(), fmt.Errorf("scanner is nil")
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
		return closedResults(), fmt.Errorf("no valid hosts resolved")
	}

	// буфер для результатов, чтобы воркеры меньше блокировались на записи в канал
	resultsCap := 4096
	if s.concurrency*2 < resultsCap {
		resultsCap = s.concurrency * 2
	}
	// буфер для очереди задач (host+port)
	jobsCap := 4096
	if s.concurrency*8 < jobsCap {
		jobsCap = s.concurrency * 8
	}

	results := make(chan Result, resultsCap)
	jobs := make(chan job, jobsCap)

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

		for _, t := range targets {
			for _, p := range portList {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{target: t, port: p}:
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
	for j := range jobs {
		select {
		case <-ctx.Done():
			// скан отменили снаружи
			return
		default:
		}
		res := s.checkOne(ctx, j.target, j.port)
		select {
		case <-ctx.Done():
			// если отмена случилась во время/после проверки не шлём результат в канал
			return
		case results <- res:
		}
	}
}

func (s *Scanner) checkOne(ctx context.Context, target hostTarget, port uint16) Result {
	start := time.Now()

	dialer := &net.Dialer{
		// этот Timeout работает как "таймаут на порт"
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

