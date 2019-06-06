package recovery

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecovery(t *testing.T) {
	stdin := strings.NewReader("all\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\ns3cr3t")
	var stdout, stderr bytes.Buffer

	if err := Run(
		WithSeedLength(12),
		UsePassphrase(true),
		WithStdin(stdin),
		WithStdout(&stdout),
		WithStderr(&stderr),
	); err != nil {
		t.Fatal(err)
	}

	expected := "53287669837134906825940750731645259835991168394122254945824146210865159709812\n110236669243376121194199083338596941870813721550167499664855109774406825623074\n"
	if stdout.String() != expected {
		t.Fatalf("unexpected output\nexpected: %s\nactual:   %s", expected, stdout.String())
	}
}
