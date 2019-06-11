package recovery

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func TestRecovery(t *testing.T) {
	var stdin, stdout, stderr bytes.Buffer

	// confirm
	fmt.Fprintln(&stdin, "yes")
	// enter the User ID
	userID := "Alice <alice@example.com>"
	fmt.Fprintln(&stdin, userID)
	// enter the timestamp
	fmt.Fprintln(&stdin, "1523060353")
	// enter the seed length
	fmt.Fprintln(&stdin, "12")
	// enter the 12 work mnemonic:
	fmt.Fprintln(&stdin, "all\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall\nall")
	// enter the passphrase:
	fmt.Fprintln(&stdin, "s3cr3t")

	// run the recovery
	if err := Run(
		WithStdin(&stdin),
		WithStdout(&stdout),
		WithStderr(&stderr),
	); err != nil {
		t.Fatal(err)
	}

	// decode the OpenPGP entity from stdout
	block, err := armor.Decode(&stdout)
	if err != nil {
		t.Fatal(err)
	}
	if block.Type != openpgp.PrivateKeyType {
		t.Fatalf("expected private key block, got %q", block.Type)
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		t.Fatal(err)
	}

	// check the entity has the correct identity
	if len(entity.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(entity.Identities))
	}
	identity, ok := entity.Identities[userID]
	if !ok {
		t.Fatal("missing identity")
	}
	if identity.UserId.Id != userID {
		t.Fatalf("expected user ID %q, got %q", userID, identity.UserId.Id)
	}

	// check the primary key fingerprint
	expectedFingerprint := "AB86C8C7B5136D19B0A6AEC0406D7920DCAD67C3"
	actualFingerprint := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint[:]))
	if actualFingerprint != expectedFingerprint {
		t.Fatalf("wrong fingerprint\nexpected: %s\nactual:   %s", expectedFingerprint, actualFingerprint)
	}

	// check the entity has one subkey
	if len(entity.Subkeys) != 1 {
		t.Fatalf("expected 1 subkey, got %d", len(entity.Subkeys))
	}

	// check the subkey fingerprint
	subkey := entity.Subkeys[0]
	expectedFingerprint = "CBE715CAA0E83224AC8F98E5CDF28C7D36F3F4F5"
	actualFingerprint = strings.ToUpper(hex.EncodeToString(subkey.PublicKey.Fingerprint[:]))
	if actualFingerprint != expectedFingerprint {
		t.Fatalf("wrong fingerprint\nexpected: %s\nactual:   %s", expectedFingerprint, actualFingerprint)
	}
}
