package recovery

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	slip10 "github.com/lmars/go-slip10"
	slip13 "github.com/lmars/go-slip13"
	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

// Run recovers a Trezor GPG identity by reading a recovery seed from stdin and
// writing the resulting identity to stdout.
func Run(opts ...Option) error {
	r := &Recovery{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
	for _, opt := range opts {
		opt(r)
	}
	r.stdinScan = bufio.NewScanner(r.stdin)
	return r.run()
}

type Recovery struct {
	stdin     io.Reader
	stdinScan *bufio.Scanner
	stdout    io.Writer
	stderr    io.Writer
}

type Option func(*Recovery)

func WithStdin(stdin io.Reader) Option {
	return func(r *Recovery) {
		r.stdin = stdin
	}
}

func WithStdout(stdout io.Writer) Option {
	return func(r *Recovery) {
		r.stdout = stdout
	}
}

func WithStderr(stderr io.Writer) Option {
	return func(r *Recovery) {
		r.stderr = stderr
	}
}

func (r *Recovery) run() error {
	// print a warning
	r.log(`
-----------------------------------------------------------------------------
                             Trezor GPG Recovery
-----------------------------------------------------------------------------
   WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING

 This program recovers private keys and prints them on the command line. You
 should only run this in a secure, controlled environment (e.g. Tails
 running from a USB stick).

   WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
-----------------------------------------------------------------------------`)

	// make sure the user wants to continue
	response, err := r.readLine(`Are you sure you want to continue with the recovery? (yes/no):`)
	if err != nil {
		return err
	} else if response != "yes" {
		return errors.New("aborting at user's request")
	}

	// prompt for the user's ID
	userID, err := r.readLine(`Please enter your GPG User ID (ex: "Alice <alice@example.com>"):`)
	if err != nil {
		return err
	}

	// prompt for the timestamp
	timestampStr, err := r.readLine("Please enter the timestamp from the original 'trezor-gpg init' command:")
	if err != nil {
		return err
	}
	timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("could not parse timestamp: %s", err)
	}
	timestamp := time.Unix(timestampInt, 0)

	// prompt for the recovery seed
	seedLengthStr, err := r.readLine(`How many words are in your Recovery Seed? (12, 18 or 24):`)
	if err != nil {
		return err
	}
	seedLength, err := strconv.Atoi(seedLengthStr)
	if err != nil {
		return err
	}
	if seedLength != 12 && seedLength != 18 && seedLength != 24 {
		return fmt.Errorf("invalid seed length %d: must be 12, 18 or 24", seedLength)
	}
	r.log("Please enter your %d word recovery seed (hit ctrl-c to exit):                ", seedLength)
	seedWords := make([]string, seedLength)
	for i := 0; i < seedLength; i++ {
		word, err := r.readWord(i + 1)
		if err != nil {
			return err
		}
		seedWords[i] = word
	}
	r.log(`-----------------------------------------------------------------------------`)

	// prompt for a passphrase
	passphrase, err := r.readLine("Please enter your passphrase (leave blank if you don't use one):")
	if err != nil {
		return err
	}

	// generate seed
	mnemonic := strings.Join(seedWords, " ")
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return err
	}

	// generate SLIP10 master key
	masterKey, err := slip10.NewMasterKeyWithCurve(seed, slip10.CurveP256)
	if err != nil {
		return err
	}

	// derive GPG primary and sub keys
	uri := "gpg://" + userID
	primaryKey, err := r.ecdsaKey(masterKey, uri, false)
	if err != nil {
		return err
	}
	subKey, err := r.ecdsaKey(masterKey, uri, true)
	if err != nil {
		return err
	}

	// construct GPG identity
	isPrimaryId := true
	entity := &openpgp.Entity{
		PrimaryKey: packet.NewECDSAPublicKey(timestamp, &primaryKey.PublicKey),
		PrivateKey: packet.NewECDSAPrivateKey(timestamp, primaryKey),
	}
	entity.Identities = map[string]*openpgp.Identity{
		userID: &openpgp.Identity{
			Name:   userID,
			UserId: &packet.UserId{Id: userID},
			SelfSignature: &packet.Signature{
				CreationTime: timestamp,
				SigType:      packet.SigTypePositiveCert,
				PubKeyAlgo:   packet.PubKeyAlgoECDSA,
				Hash:         crypto.SHA256,
				IsPrimaryId:  &isPrimaryId,
				FlagsValid:   true,
				FlagSign:     true,
				FlagCertify:  true,
				IssuerKeyId:  &entity.PrimaryKey.KeyId,
			},
		},
	}
	kdfHash, _ := s2k.HashToHashId(crypto.SHA256)
	kdfAlgo := packet.CipherAES128
	entity.Subkeys = []openpgp.Subkey{{
		PublicKey:  packet.NewECDHPublicKey(timestamp, &subKey.PublicKey, kdfHash, kdfAlgo),
		PrivateKey: packet.NewECDHPrivateKey(timestamp, subKey, kdfHash, kdfAlgo),
		Sig: &packet.Signature{
			CreationTime:              timestamp,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoECDSA,
			Hash:                      crypto.SHA256,
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &entity.PrimaryKey.KeyId,
		},
	}}
	entity.Subkeys[0].PublicKey.IsSubkey = true
	entity.Subkeys[0].PrivateKey.IsSubkey = true

	// print information about the GPG identity
	r.log(`
GPG User ID:             %s

Primary Key Fingerprint: %s

Subkey Fingerprint:      %s
`,
		userID,
		r.formatFingerprint(entity.PrimaryKey),
		r.formatFingerprint(entity.Subkeys[0].PublicKey),
	)

	// print the ascii armored private key
	privKey, err := r.serializePrivate(entity)
	if err != nil {
		return err
	}
	fmt.Fprintln(r.stdout, privKey)

	return nil
}

func (r *Recovery) log(format string, args ...interface{}) {
	fmt.Fprintln(r.stderr, fmt.Sprintf(format, args...))
}

func (r *Recovery) readLine(prompt string) (string, error) {
	fmt.Fprintf(r.stderr, "%-77s\n> ", prompt)
	defer fmt.Fprintln(r.stderr, "-----------------------------------------------------------------------------")
	r.stdinScan.Scan()
	return r.stdinScan.Text(), r.stdinScan.Err()
}

func (r *Recovery) readWord(num int) (string, error) {
	fmt.Fprintf(r.stderr, "%2d: ", num)
	r.stdinScan.Scan()
	return r.stdinScan.Text(), r.stdinScan.Err()
}

func (r *Recovery) ecdsaKey(masterKey *slip10.Key, uri string, ecdh bool) (*ecdsa.PrivateKey, error) {
	// determine what purpose field to use
	var purpose uint32 = slip13.Purpose
	if ecdh {
		purpose = 17
	}

	// derive the SLIP13 authentication key
	key, err := slip13.DeriveWithPurpose(masterKey, purpose, uri, 0)
	if err != nil {
		return nil, err
	}

	// convert to an ecdsa.PrivateKey
	curve := elliptic.P256()
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(key.Key)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(key.Key)
	return priv, nil
}

func (r *Recovery) serializePrivate(entity *openpgp.Entity) (string, error) {
	var out bytes.Buffer
	enc, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", err
	}
	if err := entity.SerializePrivate(enc, nil); err != nil {
		return "", err
	}
	enc.Close()
	out.Write([]byte{'\n'})
	return out.String(), nil
}

func (r *Recovery) formatFingerprint(key *packet.PublicKey) string {
	return strings.ToUpper(hex.EncodeToString(key.Fingerprint[:]))
}
