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

package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCanonical(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{ "b": 1, "a": [true, false, null], "c": {"z": "x", "y": -2} }`, `{"a":[true,false,null],"b":1,"c":{"y":-2,"z":"x"}}`},
		{`"quote \" backslash \\ <&> é ✓  "`, "\"quote \\\" backslash \\\\ <&> é ✓  \""},
		{`"\u0001\t\n"`, `"\u0001\t\n"`},
		{`{"é": 1, "e": 2, "E": 3}`, `{"E":3,"e":2,"é":1}`},
		{`[]`, `[]`}, {`{}`, `{}`}, {`0`, `0`},
	}
	for _, c := range cases {
		got, err := Canonical([]byte(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("Canonical(%s) = %s, %v; want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{`1.5`, `1e3`, `-0`, `01`, `{"a":1,"a":2}`, "\"\xff\"", `{} {}`, `{"a":`, ``} {
		if got, err := Canonical([]byte(bad)); err == nil {
			t.Errorf("Canonical(%q) accepted: %s", bad, got)
		}
	}
}

// sample builds a valid export with n records, signed by priv.
func sample(t *testing.T, priv ed25519.PrivateKey, n int) map[string]any {
	t.Helper()
	tenant := "0192d0a0-0000-7000-8000-0000000000a1"
	previous := Genesis
	var recs []Record
	for i := 1; i <= n; i++ {
		r := Record{TenantID: tenant, Position: int64(i), ID: fmt.Sprintf("0192d0a0-0000-7000-8000-%012d", i),
			Type: "decisao", ActorLogin: "marina.c", Data: map[string]string{"tipo": "liberar", "nota": "<&>"},
			At: fmt.Sprintf("2026-07-01T12:00:%02d.5Z", i), PreviousHash: previous}
		r.Hash = RecordHash(r)
		previous = r.Hash
		recs = append(recs, r)
	}
	trail := map[string]any{"de_posicao": 1, "ate_posicao": n, "total": n, "hash_anterior": Genesis,
		"ultimo_hash": previous, "registros": recs}
	if n == 0 {
		trail["de_posicao"], trail["ate_posicao"], trail["registros"] = 0, 0, []Record{}
	}
	content := map[string]any{
		"formato": Format, "org": map[string]any{"login": "orbita-labs", "tenant_id": tenant},
		"periodo":   map[string]any{"de": "2026-07-01", "ate": "2026-09-30"},
		"cobertura": map[string]any{"prs_com_merge": 10, "revisados_antes": 9, "excecoes": 2, "sem_justificativa": 1},
		"excecoes": []map[string]any{{"tipo": "merge_sem_revisao", "justificada": true},
			{"tipo": "revisao_parcial", "justificada": false}},
		"trilha": trail,
	}
	return sign(t, priv, content)
}

func sign(t *testing.T, priv ed25519.PrivateKey, content map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	// Round trip so the content only holds JSON types (as the verifier reads it).
	var c map[string]any
	_ = json.Unmarshal(raw, &c)
	canon, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return map[string]any{"formato": Format, "conteudo": c, "assinatura": map[string]any{
		"algoritmo": "Ed25519", "chave_id": KeyID(pub), "chave_publica": base64.StdEncoding.EncodeToString(pub),
		"valor": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))}}
}

func newKey(t *testing.T) (ed25519.PrivateKey, *PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &PublicKey{ID: KeyID(pub), Key: pub}
}

func encode(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func records(doc map[string]any) []any {
	return doc["conteudo"].(map[string]any)["trilha"].(map[string]any)["registros"].([]any)
}

func TestVerifyValid(t *testing.T) {
	priv, pub := newKey(t)
	for _, n := range []int{0, 1, 5} {
		r := Verify(encode(t, sample(t, priv, n)), pub)
		if !r.Verified() || !r.ExternalKey || r.Records != n {
			t.Fatalf("%d records: %+v", n, r)
		}
	}
	// Without a key: verified with the file's own key, with a warning.
	r := Verify(encode(t, sample(t, priv, 3)), nil)
	if !r.Verified() || r.ExternalKey || len(r.Warnings) == 0 {
		t.Fatalf("without key: %+v", r)
	}
}

func TestVerifyTampering(t *testing.T) {
	priv, pub := newKey(t)
	other, _ := newKey(t)
	cases := map[string]func(doc map[string]any) map[string]any{
		"record changed": func(doc map[string]any) map[string]any {
			records(doc)[2].(map[string]any)["ator_login"] = "someone.else"
			return doc
		},
		"record changed and re-signed with another key": func(doc map[string]any) map[string]any {
			records(doc)[2].(map[string]any)["ator_login"] = "someone.else"
			return sign(t, other, doc["conteudo"].(map[string]any))
		},
		"middle record removed": func(doc map[string]any) map[string]any {
			tr := doc["conteudo"].(map[string]any)["trilha"].(map[string]any)
			rs := records(doc)
			tr["registros"] = append(append([]any{}, rs[:2]...), rs[3:]...)
			return doc
		},
		"last record removed": func(doc map[string]any) map[string]any {
			tr := doc["conteudo"].(map[string]any)["trilha"].(map[string]any)
			tr["registros"] = records(doc)[:4]
			return doc
		},
		"records reordered": func(doc map[string]any) map[string]any {
			rs := records(doc)
			rs[1], rs[2] = rs[2], rs[1]
			return doc
		},
		"signature swapped": func(doc map[string]any) map[string]any {
			otherDoc := sample(t, priv, 4)
			doc["assinatura"].(map[string]any)["valor"] = otherDoc["assinatura"].(map[string]any)["valor"]
			return doc
		},
		"coverage changed": func(doc map[string]any) map[string]any {
			doc["conteudo"].(map[string]any)["cobertura"].(map[string]any)["prs_com_merge"] = 1000
			return doc
		},
		"unknown format": func(doc map[string]any) map[string]any {
			doc["formato"] = "other"
			return doc
		},
	}
	for name, tamper := range cases {
		doc := tamper(sample(t, priv, 5))
		if r := Verify(encode(t, doc), pub); r.Verified() {
			t.Errorf("%s: verified", name)
		}
	}
	// Re-signed by another key without --key: the stale hash still gives it away.
	doc := sample(t, priv, 5)
	records(doc)[2].(map[string]any)["ator_login"] = "someone.else"
	if r := Verify(encode(t, sign(t, other, doc["conteudo"].(map[string]any))), nil); r.Verified() {
		t.Error("changed and re-signed record verified without a key")
	}
	// A whole file produced with another key: only the given key catches it.
	if r := Verify(encode(t, sample(t, other, 3)), pub); r.Verified() ||
		!strings.Contains(strings.Join(r.Failures, " "), "not with the given key") {
		t.Errorf("other key: %+v", r)
	}
}

func TestParsePublicKey(t *testing.T) {
	_, pub := newKey(t)
	b64 := base64.StdEncoding.EncodeToString(pub.Key)
	for _, text := range []string{
		"# CodeCorvus\nchave_id: " + pub.ID + "\npublica: " + b64 + "\n",
		b64 + "\n",
	} {
		k, err := ParsePublicKey([]byte(text))
		if err != nil || k.ID != pub.ID || !k.Key.Equal(pub.Key) {
			t.Errorf("ParsePublicKey(%q) = %+v, %v", text, k, err)
		}
	}
	for _, bad := range []string{"", "publica: abc", "chave_id: ed25519-0000000000000000\npublica: " + b64} {
		if _, err := ParsePublicKey([]byte(bad)); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted", bad)
		}
	}
}
