package portscan

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool { return true }
func (timeoutNetErr) Temporary() bool {
	return true
}

func TestPortSetRangeSwap(t *testing.T) {
	ps := Range(5, 1)
	ports, err := ps.validateAndExpand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 5 {
		t.Fatalf("expected 5 ports, got %d", len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 5 {
		t.Fatalf("unexpected ports range: first=%d last=%d", ports[0], ports[len(ports)-1])
	}
}

func TestClassifyDialErrorCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := classifyDialError(ctx, context.Canceled)
	if st != Canceled {
		t.Fatalf("expected canceled, got %s", st)
	}
}

func TestClassifyDialErrorTimeout(t *testing.T) {
	ctx := context.Background()
	st := classifyDialError(ctx, timeoutNetErr{})
	if st != Timeout {
		t.Fatalf("expected timeout, got %s", st)
	}
}

func TestClassifyDialErrorClosed(t *testing.T) {
	ctx := context.Background()
	st := classifyDialError(ctx, syscall.ECONNREFUSED)
	if st != Closed {
		t.Fatalf("expected closed, got %s", st)
	}
}

func TestScan_emptyHosts(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = s.Scan(context.Background(), []string{}, Range(1, 10))
	if err == nil {
		t.Fatal("expected error for empty hosts")
	}
	if err.Error() != "hosts must not be empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScanOpenClosed(t *testing.T) {
	lnOpen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen open: %v", err)
	}
	defer lnOpen.Close()
	openPort := lnOpen.Addr().(*net.TCPAddr).Port

	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tmp: %v", err)
	}
	closedPort := tmpLn.Addr().(*net.TCPAddr).Port
	_ = tmpLn.Close()
	time.Sleep(150 * time.Millisecond)

	s, err := New(
		WithConcurrency(10),
		WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	resultsCh, err := s.Scan(ctx, []string{"127.0.0.1"}, Ports(openPort, closedPort))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got := make(map[uint16]State)
	for r := range resultsCh {
		got[r.Port] = r.State
	}

	if got[uint16(openPort)] != Open {
		t.Fatalf("expected open port=%d to be open, got %s", openPort, got[uint16(openPort)])
	}
	if got[uint16(closedPort)] != Closed {
		t.Fatalf("expected closed port=%d to be closed, got %s", closedPort, got[uint16(closedPort)])
	}
}

