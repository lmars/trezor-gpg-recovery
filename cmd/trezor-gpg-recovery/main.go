package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	recovery "github.com/lmars/trezor-gpg-recovery"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	// quit on SIGINT or SIGTERM
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		os.Exit(0)
	}()

	// run recovery
	return recovery.Run()
}
