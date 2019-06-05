package recovery

import (
	"fmt"
	"io"
	"os"

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
	return r.run()
}

type Recovery struct {
	stdin         io.Reader
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
	// prompt for the recovery seed
	if r.isInteractive {
		r.log("Please enter your %d word recovery seed (hit ctrl-c to exit):", r.seedLength)
	}
	seed := make([]string, r.seedLength)
	for i := 0; i < r.seedLength; i++ {
		prompt := fmt.Sprintf("%2d: ", i+1)
		word, err := r.readLine(prompt)
		if err != nil {
			return err
		}
		seed[i] = word
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

	fmt.Fprintln(r.stdout, append(seed, passphrase))

	return nil
}

func (r *Recovery) log(format string, args ...interface{}) {
	fmt.Fprintln(r.stderr, fmt.Sprintf(format, args...))
}

func (r *Recovery) readLine(prompt string) (string, error) {
	if r.isInteractive {
		fmt.Fprintf(r.stderr, prompt)
	}
	var line string
	_, err := fmt.Fscanln(r.stdin, &line)
	return line, err
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
