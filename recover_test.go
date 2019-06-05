package recovery

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestRecovery(t *testing.T) {
	for _, length := range []int{12, 18, 24} {
		t.Run(fmt.Sprintf("seed length %d", length), func(t *testing.T) {
			testRecoveryWithSeedLength(t, length)
		})
	}
}

func testRecoveryWithSeedLength(t *testing.T, seedLength int) {
	seed := make([]string, seedLength)
	for i := 0; i < seedLength; i++ {
		seed[i] = "all"
	}
	passphrase := "s3cr3t"

	stdin := strings.NewReader(strings.Join(append(seed, passphrase), "\n"))
	var stdout, stderr bytes.Buffer

	if err := Run(
		WithSeedLength(seedLength),
		UsePassphrase(true),
		WithStdin(stdin),
		WithStdout(&stdout),
		WithStderr(&stderr),
	); err != nil {
		t.Fatal(err)
	}

	expected := fmt.Sprintln(append(seed, passphrase))
	if stdout.String() != expected {
		t.Fatalf("unexpected output\nexpected: %s\nactual:   %s", expected, stdout.String())
	}
}
