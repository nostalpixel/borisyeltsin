# Security

BorisYeltsin encrypts vault payloads in the browser. It does not encrypt the subscription ledger. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before storing real credentials, and [docs/CRYPTO.md](docs/CRYPTO.md) for the constructions.

## Report a problem

Open a private security advisory on `github.com/nostalpixel/borisyeltsin`, or email the maintainer if you cannot use advisories. Please include a reproduction and the version you built. Give the project time to fix a vulnerability before publishing it.

Do not include passphrases, recovery keys, or vault plaintext in the report.

## Limits

This application does not claim protection against malware on an unlocked device, malicious JavaScript from a compromised server, credentials a former member already copied, a full identity-provider compromise combined with stolen unlock material, or two recovery custodians working together.

An Authentik password reset does not unlock the vault. If the passphrase, the personal recovery key, and both organization shares are gone, the ciphertext stays unreadable.

The audit log cannot prove that a browser did not copy a password, and a database administrator can change ordinary audit rows.

An independent review of [docs/CRYPTO.md](docs/CRYPTO.md) is still required before the vault holds real organizational credentials.
