# Trezor GPG Recovery

A utility to recover a [Trezor GPG identity](https://wiki.trezor.io/GPG)
using a [recovery seed](https://wiki.trezor.io/Recovery_seed).

---

**WARNING WARNING WARNING**

This program recovers private keys and prints them on the command line. You should
only run this in a secure, controlled environment (e.g. Tails running from a USB stick).

**WARNING WARNING WARNING**

---

## Install

Install a recent version of Go (>=1.12) and build the CLI command:

```
$ cd path/to/trezor-gpg-recovery

$ go build ./cmd/trezor-gpg-recovery
```

This builds a CLI binary in the current directory (`./trezor-gpg-recovery`).

## Usage

To run recovery, you'll need:

- The exact GPG User ID originally passed to `trezor-gpg init` (e.g. `Alice <alice@example.com>`)

- The exact timestamp from the original call to `trezor-gpg init` (e.g. `1560262986`, see [here](https://github.com/romanz/trezor-agent/blob/master/doc/README-GPG.md#re-generate-a-gpg-identity) if you're unsure what this is)

- Your [Recovery Seed](https://wiki.trezor.io/Recovery_seed)

- Your passphrase (optional)

Run the recovery program that will prompt for these:

```
$ ./trezor-gpg-recovery

-----------------------------------------------------------------------------
                             Trezor GPG Recovery
-----------------------------------------------------------------------------
   WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING

 This program recovers private keys and prints them on the command line. You
 should only run this in a secure, controlled environment (e.g. Tails
 running from a USB stick).

   WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
-----------------------------------------------------------------------------
Are you sure you want to continue with the recovery? (yes/no):
> yes
-----------------------------------------------------------------------------
Please enter your GPG User ID (ex: "Alice <alice@example.com>"):
> Bob <bob@example.com>
-----------------------------------------------------------------------------
Please enter the timestamp from the original 'trezor-gpg init' command:
> 1560262986
-----------------------------------------------------------------------------
How many words are in your Recovery Seed? (12, 18 or 24):
> 12
-----------------------------------------------------------------------------
Please enter your 12 word recovery seed (hit ctrl-c to exit):
 1: zoo
 2: zoo
 3: zoo
 4: zoo
 5: zoo
 6: zoo
 7: zoo
 8: zoo
 9: zoo
10: zoo
11: zoo
12: wrong
-----------------------------------------------------------------------------
Please enter your passphrase (leave blank if you don't use one):
> s3cr3t
-----------------------------------------------------------------------------

GPG User ID:             Bob <bob@example.com>

Primary Key Fingerprint: AB56AE89922A6BB4DCC7F7A6BEFE43CEA0BEC4E5

Subkey Fingerprint:      1136A8CF400AE1AAFF7C7BC769799BB5DF9B1B8C

-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEXP+5ShMIKoZIzj0DAQcCAwSjWH9wwHRBKIwWN6UU/N+bKzR/B2WEIsVzNLs7
dCmB8OsfYl1JQZf5ilTYh0XZedIk1qfzqXKGNx7cLkzIaL+aAAD/W7F5FLSGekpO
p+vJAtwd5Qhyflsnc9iOPfoYS7WS0DkQXM0VQm9iIDxib2JAZXhhbXBsZS5jb20+
wmQEExMIABYFAlz/uUoJEL7+Q86gvsTlAhsDAhkBAACmCwD/e7gLOkEr5q3UVGju
6UtB93yWuNKLe1UT1ek3fD85gVIBAN1dgotQHS9bzdUaciZb4tsLYlrWIqFII9R1
2JCEO3pox3sEXP+5ShIIKoZIzj0DAQcCAwRPQxyo4w55yHCp/5A/KeBBS4wChHcq
TycmzRIXiUznt8eBsMBE6soOve+41DbsO9qdn7cqAq3wxB7BBnkQfqA+AwEIBwAA
/0oasDn0NTTe4Q2Cp303qIoTvnTCjyzyxqUqcrOEJSr5EL7CYQQYEwgAEwUCXP+5
SgkQvv5DzqC+xOUCGwwAAOeLAP9grXfhJrGkWXgYOmTPV/WKI7fXb2nnnAZ89zfN
pHzNYwD+LTzTBO+7TiYKZZqxv7aQznqyscNEZrnlilBAreAZXdw=
=Iux3
-----END PGP PRIVATE KEY BLOCK-----

```

You can now copy the printed private key block to a file and run `gpg --import` to import
it into the local keychain.
