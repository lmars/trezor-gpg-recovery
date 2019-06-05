package recovery

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecovery(t *testing.T) {
	stdin := strings.NewReader("all\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\n")
	var stdout, stderr bytes.Buffer

	if err := Run(
		WithStdin(stdin),
		WithStdout(&stdout),
		WithStderr(&stderr),
	); err != nil {
		t.Fatal(err)
	}

	expected := "[all all all all all all all all all all all all all all all all all all all all all all all all]\n"
	if stdout.String() != expected {
		t.Fatalf("unexpected output\nexpected: %s\nactual:   %s", expected, stdout.String())
	}
}
