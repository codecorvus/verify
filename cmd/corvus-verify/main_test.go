// Copyright 2026 CodeCorvus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codecorvus/verify"
)

// validFile writes an empty signed export and its public key.
func validFile(t *testing.T) (doc, pub string) {
	t.Helper()
	pk, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"formato":"` + verify.Format + `","org":{"login":"orbita-labs","tenant_id":"t"},` +
		`"periodo":{"de":"2026-07-01","ate":"2026-09-30"},"cobertura":{"prs_com_merge":0,"revisados_antes":0,` +
		`"excecoes":0,"sem_justificativa":0},"excecoes":[],"trilha":{"de_posicao":0,"ate_posicao":0,"total":0,` +
		`"hash_anterior":"","ultimo_hash":"","registros":[]}}`)
	canon, err := verify.Canonical(content)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := json.Marshal(map[string]any{"formato": verify.Format, "conteudo": json.RawMessage(content),
		"assinatura": map[string]string{"algoritmo": "Ed25519", "chave_id": verify.KeyID(pk),
			"chave_publica": base64.StdEncoding.EncodeToString(pk),
			"valor":         base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))}})
	dir := t.TempDir()
	doc, pub = filepath.Join(dir, "export.json"), filepath.Join(dir, "codecorvus-evidencia.pub")
	if err := os.WriteFile(doc, d, 0o600); err != nil {
		t.Fatal(err)
	}
	text := "chave_id: " + verify.KeyID(pk) + "\npublica: " + base64.StdEncoding.EncodeToString(pk) + "\n"
	if err := os.WriteFile(pub, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return doc, pub
}

func TestRun(t *testing.T) {
	doc, pub := validFile(t)
	var stdout, stderr bytes.Buffer
	if c := run([]string{doc, "--key", pub}, &stdout, &stderr); c != 0 || !strings.Contains(stdout.String(), "result: VERIFIED") {
		t.Fatalf("valid: exit %d\n%s%s", c, stdout.String(), stderr.String())
	}
	raw, _ := os.ReadFile(doc)
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	_ = os.WriteFile(tampered, bytes.Replace(raw, []byte(`"prs_com_merge":0`), []byte(`"prs_com_merge":1`), 1), 0o600)
	stdout.Reset()
	if c := run([]string{tampered, "--key", pub}, &stdout, &stderr); c != 1 || !strings.Contains(stdout.String(), "NOT VERIFIED") {
		t.Fatalf("tampered: exit %d\n%s", c, stdout.String())
	}
	for _, args := range [][]string{{}, {doc, "--key"}, {filepath.Join(t.TempDir(), "missing.json")}, {doc, "extra"},
		{doc, "--key", doc}} {
		if c := run(args, &stdout, &stderr); c != 2 {
			t.Errorf("run(%v) = %d; want 2", args, c)
		}
	}
}
