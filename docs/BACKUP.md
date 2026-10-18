# Backup and restore

Two different backups exist. They protect different things.

## Database

Postgres holds users, sessions, services, subscriptions, audit rows, public keys, and every ciphertext. The Compose volume is `postgres-data`. The database port is not published. Run dumps from inside the Compose network.

```bash
docker compose exec -T postgres pg_dump -U boriseltsyn -d boriseltsyn --format=custom > boriseltsyn.dump
```

`POSTGRES_PASSWORD` must already be set. The dump contains ciphertext and metadata. It does not contain passphrases, private keys, personal recovery keys, or unsealed shares. Store the dump where the people who hold those keys are not the only people who can lose them, and protect the dump like the metadata it is: names of services, prices, and who has access.

Restore into an empty database:

```bash
docker compose exec -T postgres pg_restore -U boriseltsyn -d boriseltsyn --clean --if-exists < boriseltsyn.dump
```

Stop the application container before a restore so it is not writing. Start it again after `pg_restore` finishes. Migrations run on startup and are a no-op when the schema is already current.

A restore brings old session rows back. Revoke users or delete sessions if those cookies should be dead. See `RECOVERY.md`.

### Restore drill

A dump you have never restored is a guess. Run the drill from the directory that holds `docker-compose.yml`:

```bash
scripts/restore-drill.sh
```

It dumps the live database, restores the dump into a scratch database in the same Postgres container, compares row counts for every table, and drops the scratch database. The live database is only read, and the application keeps running. Run it at a quiet moment: a write between the count and the dump shows up as a mismatch, and the drill then fails. CI runs the same script on every push.

The drill proves the dump restores. It does not prove anyone can still open the vault. That needs the keys listed below.

Before deploying a release with a migration, take a dump. Migration `003` (organization recovery format 2) is one-way: it deletes the old recovery shares, and custodians enroll again afterwards. Going back to an older release means restoring the dump taken before the upgrade.

Copying the `postgres-data` volume is a cold backup only when Postgres is stopped. A copy of a running data directory can be torn. Prefer `pg_dump`.

## Service export

CSV and XLSX exports list services and accounts. They omit passwords. The old spreadsheet this product replaces included passwords. This one does not.

JSON import accepts the reference shape:

```json
{
  "version": 1,
  "services": [
    {
      "name": "Example",
      "url": "https://example.com",
      "category": "tools",
      "description": "",
      "unclear": false,
      "logo": "",
      "bg": "#7161d2",
      "fg": "#ffffff",
      "accounts": [
        {
          "label": "Main",
          "login": "ops",
          "password": "",
          "cost": "12.50",
          "currency": "USD",
          "date": "2026-11-01",
          "card": "Card · 4242",
          "notes": ""
        }
      ]
    }
  ]
}
```

The browser deletes `password`, encrypts a non-empty password into a vault item, and posts the rest. The API rejects a body that still contains a non-empty secret field or a 13–19 digit card number. Import creates a monthly subscription from `cost`. The editor can later change the cycle to quarterly, annual, or custom.

An export is not a vault backup. Restoring it recreates metadata only.

## What a complete backup is

Keep all of these, in separate places:

- Postgres dumps.
- Each member's personal recovery key, stored when enrollment showed it.
- The recovery custodians' ability to open their own key: each custodian's passphrase or personal recovery key. Their boxed shares are already in the database dump.
- The Authentik configuration, which this repository does not back up.

Losing the dump loses the ciphertext. Losing the keys loses the ability to read a dump you still have.
