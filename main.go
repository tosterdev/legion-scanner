package main

import (
	"context"
	"fmt"
	"legion-scanner/portscan"
	"os"
	"time"
)

func main() {
	ctx := context.Background()

	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	results, err := scanner.Scan(
		ctx,
		[]string{"192.168.1.10", "192.168.1.11"},
		portscan.Range(1, 1000),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for result := range results {
		fmt.Printf(
			"%s:%d %s\n",
			result.Host,
			result.Port,
			result.State.String(),
		)
	}

}
