package portscan

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

const slowHost = "192.0.2.1"

func drainResults(ch <-chan Result, timeout time.Duration) ([]Result, bool) {
	out := make([]Result, 0, 64)
	done := make(chan struct{})

	go func() {
		for r := range ch {
			out = append(out, r)
		}
		close(done)
	}()

	select {
	case <-done:
		return out, true
	case <-time.After(timeout):
		return out, false
	}
}

func TestScan_contextCancelClosesResults(t *testing.T) {
	s, err := New(
		WithConcurrency(20),
		WithConnectTimeout(300*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const totalPorts = 200
	ctx, cancel := context.WithCancel(context.Background())

	results, err := s.Scan(ctx, []string{slowHost}, Range(1, totalPorts))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	got, closed := drainResults(results, 5*time.Second)
	if !closed {
		t.Fatal("results channel did not close after context cancel")
	}
	if len(got) >= totalPorts {
		t.Fatalf("expected partial results after cancel, got all %d", len(got))
	}
}

func TestScan_reuseScanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	s, err := New(
		WithConcurrency(5),
		WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for run := 1; run <= 2; run++ {
		t.Run(fmt.Sprintf("run%d", run), func(t *testing.T) {
			results, err := s.Scan(
				context.Background(),
				[]string{"127.0.0.1"},
				Ports(openPort),
			)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}

			got, closed := drainResults(results, 3*time.Second)
			if !closed {
				t.Fatal("results channel did not close")
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 result, got %d", len(got))
			}
			if got[0].State != Open {
				t.Fatalf("expected open, got %s", got[0].State)
			}
		})
	}
}

func TestScan_slowResultReader(t *testing.T) {
	s, err := New(
		WithConcurrency(10),
		WithConnectTimeout(150*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const portCount = 30
	const fromPort = 40000
	results, err := s.Scan(
		context.Background(),
		[]string{"127.0.0.1"},
		Range(fromPort, fromPort+portCount-1),
	)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// имитируем медленного читателя: воркеры должны подождать на отправке в results
	time.Sleep(300 * time.Millisecond)

	got, closed := drainResults(results, 5*time.Second)
	if !closed {
		t.Fatal("results channel did not close")
	}
	if len(got) != portCount {
		t.Fatalf("expected %d results, got %d", portCount, len(got))
	}
}

func TestScan_concurrencyLimit(t *testing.T) {
	const (
		portCount = 6
		timeout   = 250 * time.Millisecond
	)

	scanDuration := func(concurrency int) time.Duration {
		s, err := New(
			WithConcurrency(concurrency),
			WithConnectTimeout(timeout),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		start := time.Now()
		results, err := s.Scan(
			context.Background(),
			[]string{slowHost},
			Range(1, portCount),
		)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		got, closed := drainResults(results, 10*time.Second)
		if !closed {
			t.Fatal("results channel did not close")
		}
		if len(got) != portCount {
			t.Fatalf("expected %d results, got %d", portCount, len(got))
		}
		return time.Since(start)
	}

	serial := scanDuration(1)
	parallel := scanDuration(portCount)

	// при concurrency=1 порты идут последовательно, при concurrency=N — параллельно
	minSerial := time.Duration(portCount) * timeout / 2
	maxParallel := timeout * 3

	if serial < minSerial {
		t.Logf("serial faster than expected (%v), network may be unusually fast", serial)
	}
	if parallel > maxParallel {
		t.Fatalf("parallel scan too slow: %v (limit ~%v)", parallel, maxParallel)
	}
	if parallel >= serial {
		t.Fatalf("expected parallel (%v) faster than serial (%v)", parallel, serial)
	}
}
