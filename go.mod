module github.com/lmars/trezor-gpg-recovery

go 1.12

require (
	github.com/lmars/go-slip10 v0.0.0-20190606092855-400ba44fee12
	github.com/lmars/go-slip13 v0.0.0-20190606122626-90adb8bf5e28
	github.com/tyler-smith/go-bip39 v1.0.0
	golang.org/x/crypto v0.0.0-20190605123033-f99c8df09eb5
)

replace golang.org/x/crypto => github.com/lmars/crypto v0.0.0-20190611121552-821fa1c75010
