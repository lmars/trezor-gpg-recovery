package recovery

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
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
	"golang.org/x/crypto/ssh/terminal"
)

// DefaultSeedLength is the default value for the expected length of the
// recovery seed.
const DefaultSeedLength = 24

// Run recovers a Trezor GPG identity by reading a recovery seed from stdin and
// writing the resulting identity to stdout.
func Run(opts ...Option) error {
	r := &Recovery{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		seedLength: DefaultSeedLength,
	}
	for _, opt := range opts {
		opt(r)
	}
	if err := r.validate(); err != nil {
		return err
	}
	if f, ok := r.stdin.(*os.File); ok && terminal.IsTerminal(int(f.Fd())) {
		r.isInteractive = true
	}
	r.stdinScan = bufio.NewScanner(r.stdin)
	return r.run()
}

type Recovery struct {
	stdin         io.Reader
	stdinScan     *bufio.Scanner
	stdout        io.Writer
	stderr        io.Writer
	seedLength    int
	isInteractive bool
	usePassphrase bool
}

type Option func(*Recovery)

func WithSeedLength(seedLength int) Option {
	return func(r *Recovery) {
		r.seedLength = seedLength
	}
}

func UsePassphrase(usePassphrase bool) Option {
	return func(r *Recovery) {
		r.usePassphrase = usePassphrase
	}
}

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
	// prompt for the user's ID
	userID, err := r.readLine(`Please enter your GPG User ID (ex: "Alice <alice@example.com>"): `)
	if err != nil {
		return err
	}

	// prompt for the timestamp
	timestampStr, err := r.readLine("Please enter the timestamp from the original 'trezor-gpg init' command: ")
	if err != nil {
		return err
	}
	timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("could not parse timestamp: %s", err)
	}
	timestamp := time.Unix(timestampInt, 0)

	// prompt for the recovery seed
	if r.isInteractive {
		r.log("Please enter your %d word recovery seed (hit ctrl-c to exit):", r.seedLength)
	}
	seedWords := make([]string, r.seedLength)
	for i := 0; i < r.seedLength; i++ {
		prompt := fmt.Sprintf("%2d: ", i+1)
		word, err := r.readLine(prompt)
		if err != nil {
			return err
		}
		seedWords[i] = word
	}

	// prompt for a passphrase
	var passphrase string
	if r.usePassphrase {
		var err error
		passphrase, err = r.readLine("Please enter your passphrase: ")
		if err != nil {
			return err
		}
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
	fmt.Fprintln(r.stderr, "User ID:", userID)
	fmt.Fprintln(r.stderr, "Primary Key:", r.formatFingerprint(entity.PrimaryKey))
	fmt.Fprintln(r.stderr, "Sub Key:", r.formatFingerprint(entity.Subkeys[0].PublicKey))

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
	if r.isInteractive {
		fmt.Fprintf(r.stderr, prompt)
	}
	r.stdinScan.Scan()
	return r.stdinScan.Text(), r.stdinScan.Err()
}

var validSeedLengths = []int{12, 18, 24}

func (r *Recovery) validate() error {
	validSeedLength := false
	for _, l := range validSeedLengths {
		if r.seedLength == l {
			validSeedLength = true
			break
		}
	}
	if !validSeedLength {
		return fmt.Errorf("invalid seed length %d, must be one of %v", r.seedLength, validSeedLengths)
	}
	return nil
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
