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

	expected := "554bf29ce4a20616e16d3dbe7d4c733dfc6cbd7769648d8985f1735ab74ce635b09edc3971f111aede79827e7bde14c3e4b30066ae4bede2070fc7f1ad3c12cb\n"
	if stdout.String() != expected {
		t.Fatalf("unexpected output\nexpected: %s\nactual:   %s", expected, stdout.String())
	}
}
