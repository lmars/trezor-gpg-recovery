package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	recovery "github.com/lmars/trezor-gpg-recovery"
)

var seedLength = flag.Int(
	"len",
	recovery.DefaultSeedLength,
	fmt.Sprintf("Length of the Recovery Seed (default: %d)", recovery.DefaultSeedLength),
)

var usePassphrase = flag.Bool(
	"pass",
	false,
	"Prompt for a passphrase (default: false)",
)

func main() {
	flag.Parse()

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
	return recovery.Run(
		recovery.WithSeedLength(*seedLength),
		recovery.UsePassphrase(*usePassphrase),
	)
}
