package recovery

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	slip10 "github.com/lmars/go-slip10"
	slip13 "github.com/lmars/go-slip13"
	bip39 "github.com/tyler-smith/go-bip39"
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

	fmt.Fprintln(r.stdout, primaryKey.D)
	fmt.Fprintln(r.stdout, subKey.D)

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
