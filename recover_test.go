package recovery

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRecovery(t *testing.T) {
	var stdin, stdout, stderr bytes.Buffer

	// enter the User ID:
	fmt.Fprintln(&stdin, "Alice <alice@example.com>")
	// enter a 12 work mnemonic:
	fmt.Fprintln(&stdin, "all\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall")
	// enter a passphrase:
	fmt.Fprintln(&stdin, "s3cr3t")

	// run the recovery
	if err := Run(
		WithSeedLength(12),
		UsePassphrase(true),
		WithStdin(&stdin),
		WithStdout(&stdout),
		WithStderr(&stderr),
	); err != nil {
		t.Fatal(err)
	}

	expected := "86774768610136898273622707509188377053800737438658011629694106432640461915797\n103638615045368953345369873210273481442496506251330185938949065376181864001778\n"
	if stdout.String() != expected {
		t.Fatalf("unexpected output\nexpected: %s\nactual:   %s", expected, stdout.String())
	}
}
