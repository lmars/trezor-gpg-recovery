package recovery

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh/terminal"
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
	if f, ok := r.stdin.(*os.File); ok && terminal.IsTerminal(int(f.Fd())) {
		r.isInteractive = true
	}
	return r.run()
}

type Recovery struct {
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	isInteractive bool
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
	// prompt for the recovery seed
	if r.isInteractive {
		r.log("Please enter your 24 word recovery seed (hit ctrl-c to exit):")
	}
	seed := make([]string, 24)
	for i := 0; i < 24; i++ {
		word, err := r.readWord(i + 1)
		if err != nil {
			return err
		}
		seed[i] = word
	}

	fmt.Fprintln(r.stdout, seed)

	return nil
}

func (r *Recovery) log(format string, args ...interface{}) {
	fmt.Fprintln(r.stderr, fmt.Sprintf(format, args...))
}

func (r *Recovery) readWord(num int) (string, error) {
	if r.isInteractive {
		fmt.Fprintf(r.stderr, "%2d: ", num)
	}
	var word string
	_, err := fmt.Fscanln(r.stdin, &word)
	return word, err
}
