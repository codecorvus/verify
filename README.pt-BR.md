<!-- Copyright 2026 CodeCorvus · SPDX-License-Identifier: Apache-2.0 -->

# corvus-verify

Verificador independente da exportação de evidência do CodeCorvus (formato `codecorvus.exportacao-evidencia.v1`).
Roda sem rede e sem o CodeCorvus: quem audita baixa a exportação no painel (Evidência → Exportar evidência), pega a
chave pública e confere tudo na própria máquina.

[Read in English](README.md)

## Uso

```
go install github.com/codecorvus/verify/cmd/corvus-verify@latest
curl -O https://<seu-codecorvus>/.well-known/codecorvus-evidencia.pub
corvus-verify exportacao.json --key codecorvus-evidencia.pub
```

Saída: `0` verificada; `1` não verificada (cada motivo numa linha `FAILED:`); `2` uso errado ou arquivo ilegível. As
mensagens da ferramenta são em inglês.

## O que é conferido

- **Assinatura**: Ed25519 sobre a forma canônica do objeto `conteudo`. Com `--key`, a assinatura tem de ser dessa
  chave (a publicada em `/.well-known/codecorvus-evidencia.pub`, identificada pelo `chave_id`). Sem `--key`, vale a
  chave pública do próprio arquivo, e a saída avisa que a autoria não ficou provada.
- **Hash de cada registro**: recalculado como `sha256(hash_anterior + "\n" + JSON do registro)`.
- **Encadeamento**: cada registro aponta para o hash do anterior; o primeiro, para o hash anterior declarado (64 zeros
  quando a exportação começa na posição 1).
- **Lacunas**: posições contíguas de `de_posicao` a `ate_posicao`, total de registros igual a `total` e último hash
  igual a `ultimo_hash`. Registro removido, inserido ou reordenado falha.
- **Totais**: o número de exceções e de exceções sem justificativa bate com a lista.

A ferramenta só lê o arquivo que você der: sem rede, sem subprocesso, só a biblioteca padrão do Go.

## Chave pública

A instalação do CodeCorvus publica a chave, sem login, em `/.well-known/codecorvus-evidencia.pub`:

```
# CodeCorvus · chave pública da exportação de evidência (Ed25519)
chave_id: ed25519-1a2b3c4d5e6f7a8b
publica: <32 bytes em base64>
```

O `chave_id` é `ed25519-` seguido dos 16 primeiros dígitos hex do sha256 da chave pública. `--key` também aceita um
arquivo só com a chave em base64.

## Formato

O JSON Schema está em [`schema/exportacao-evidencia.v1.json`](schema/exportacao-evidencia.v1.json); a descrição dele
detalha a forma canônica, o hash do registro e as regras de encadeamento, para conferir com outras ferramentas também.

## Licença

Apache-2.0 (veja [LICENSE](LICENSE)).
