<!-- Copyright 2026 CodeCorvus · SPDX-License-Identifier: Apache-2.0 -->

# corvus-verify

Independent verifier for CodeCorvus evidence exports (format `codecorvus.exportacao-evidencia.v1`). It runs offline,
with no network access and without CodeCorvus: an auditor downloads the export from the dashboard (Evidência →
Exportar evidência), fetches the public key and checks everything on their own machine.

[Leia em português](README.pt-BR.md)

## Usage

```
go install github.com/codecorvus/verify/cmd/corvus-verify@latest
curl -O https://<your-codecorvus-host>/.well-known/codecorvus-evidencia.pub
corvus-verify export.json --key codecorvus-evidencia.pub
```

Exit status: `0` verified; `1` not verified (each reason is printed on a `FAILED:` line); `2` usage error or
unreadable file.

## What is checked

- **Signature**: Ed25519 over the canonical form of the `conteudo` object. With `--key`, the signature must come from
  that key (the one published at `/.well-known/codecorvus-evidencia.pub`, identified by `chave_id`). Without `--key`,
  the public key embedded in the file is used and the output warns that authorship was not proven.
- **Record hashes**: each audit-trail record's hash is recomputed as `sha256(previous_hash + "\n" + record JSON)`.
- **Chaining**: every record points to the hash of the previous one; the first one points to the declared previous
  hash (64 zeros when the export starts at position 1).
- **Gaps**: positions are contiguous from `de_posicao` to `ate_posicao`, the record count matches `total` and the last
  hash matches `ultimo_hash`. A removed, inserted or reordered record fails.
- **Totals**: the number of exceptions and of exceptions without justification match the list.

The tool only reads the file you give it: no network, no subprocesses, standard library only.

## Public key

The CodeCorvus deployment serves its public key, with no login, at `/.well-known/codecorvus-evidencia.pub`:

```
# CodeCorvus · chave pública da exportação de evidência (Ed25519)
chave_id: ed25519-1a2b3c4d5e6f7a8b
publica: <32 bytes in base64>
```

`chave_id` is `ed25519-` followed by the first 16 hex digits of the sha256 of the public key. `--key` also accepts a
file holding just the base64 key.

## Format

The JSON Schema is in [`schema/exportacao-evidencia.v1.json`](schema/exportacao-evidencia.v1.json); its description
spells out the canonical form, the record hash and the chaining rules, so the export can be checked with other tools
too. Field names are in Portuguese, as exported.

## License

Apache-2.0 (see [LICENSE](LICENSE)).
