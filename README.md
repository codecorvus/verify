<!-- Copyright 2026 CodeCorvus · SPDX-License-Identifier: Apache-2.0 -->

# corvus-verify

Independent verifier for CodeCorvus evidence exports (format `codecorvus.evidence-export.v1`). It runs offline,
with no network access and without CodeCorvus: an auditor downloads the export from the dashboard (Evidência →
Exportar evidência), fetches the public key and checks everything on their own machine.

[Leia em português](README.pt-BR.md)

## Usage

```
go install github.com/codecorvus/verify/cmd/corvus-verify@latest
curl -O https://<your-codecorvus-host>/.well-known/codecorvus-evidence.pub
corvus-verify export.json --key codecorvus-evidence.pub
```

Exit status: `0` verified; `1` not verified (each reason is printed on a `FAILED:` line); `2` usage error or
unreadable file.

## What is checked

- **Signature**: Ed25519 over the canonical form of the `content` object. With `--key`, the signature must come from
  that key (the one published at `/.well-known/codecorvus-evidence.pub`, identified by `key_id`). Without `--key`,
  the public key embedded in the file is used and the output warns that authorship was not proven.
- **Record hashes**: each audit-trail record's hash is recomputed as `sha256(previous_hash + "\n" + record JSON)`.
- **Chaining**: every record points to the hash of the previous one; the first one points to the declared previous
  hash (64 zeros when the export starts at position 1).
- **Gaps**: positions are contiguous from `from_position` to `to_position`, the record count matches `total` and the
  last hash matches `last_hash`. A removed, inserted or reordered record fails.
- **Totals**: the number of exceptions and of unjustified exceptions match the list.

The tool only reads the file you give it: no network, no subprocesses, standard library only.

## Public key

The CodeCorvus deployment serves its public key, with no login, at `/.well-known/codecorvus-evidence.pub`:

```
# CodeCorvus · evidence export public key (Ed25519)
key_id: ed25519-1a2b3c4d5e6f7a8b
public_key: <32 bytes in base64>
```

`key_id` is `ed25519-` followed by the first 16 hex digits of the sha256 of the public key. `--key` also accepts a
file holding just the base64 key.

## Format

The JSON Schema is in [`schema/evidence-export.v1.json`](schema/evidence-export.v1.json); its description spells
out the canonical form, the record hash and the chaining rules, so the export can be checked with other tools too.

The record hash is computed over the record as the audit trail stores it, with a fixed list of keys that differs
from the export field names (`position` is hashed as `posicao`, `type` as `tipo`, and so on; the schema has the full
list, in order). That list is part of the format: it keeps records written before this format verifiable.

## License

Apache-2.0 (see [LICENSE](LICENSE)).
