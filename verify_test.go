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
	"os"
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
			Type: "decisao", ActorLogin: "jane.doe", Data: map[string]string{"tipo": "liberar", "nota": "<&>"},
			At: fmt.Sprintf("2026-07-01T12:00:%02d.5Z", i), PreviousHash: previous}
		r.Hash = RecordHash(r)
		previous = r.Hash
		recs = append(recs, r)
	}
	trail := map[string]any{"from_position": 1, "to_position": n, "total": n, "previous_hash": Genesis,
		"last_hash": previous, "records": recs}
	if n == 0 {
		trail["from_position"], trail["to_position"], trail["records"] = 0, 0, []Record{}
	}
	content := map[string]any{
		"format": Format, "org": map[string]any{"login": "example-org", "tenant_id": tenant},
		"period":   map[string]any{"from": "2026-07-01", "to": "2026-09-30"},
		"coverage": map[string]any{"merged_prs": 10, "reviewed_before_merge": 9, "exceptions": 2, "unjustified": 1},
		"exceptions": []map[string]any{{"type": "merge_sem_revisao", "justified": true},
			{"type": "revisao_parcial", "justified": false}},
		"trail": trail,
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
	return map[string]any{"format": Format, "content": c, "signature": map[string]any{
		"algorithm": "Ed25519", "key_id": KeyID(pub), "public_key": base64.StdEncoding.EncodeToString(pub),
		"value": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))}}
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
	return doc["content"].(map[string]any)["trail"].(map[string]any)["records"].([]any)
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
			records(doc)[2].(map[string]any)["actor_login"] = "someone.else"
			return doc
		},
		"record changed and re-signed with another key": func(doc map[string]any) map[string]any {
			records(doc)[2].(map[string]any)["actor_login"] = "someone.else"
			return sign(t, other, doc["content"].(map[string]any))
		},
		"middle record removed": func(doc map[string]any) map[string]any {
			tr := doc["content"].(map[string]any)["trail"].(map[string]any)
			rs := records(doc)
			tr["records"] = append(append([]any{}, rs[:2]...), rs[3:]...)
			return doc
		},
		"last record removed": func(doc map[string]any) map[string]any {
			tr := doc["content"].(map[string]any)["trail"].(map[string]any)
			tr["records"] = records(doc)[:4]
			return doc
		},
		"records reordered": func(doc map[string]any) map[string]any {
			rs := records(doc)
			rs[1], rs[2] = rs[2], rs[1]
			return doc
		},
		"signature swapped": func(doc map[string]any) map[string]any {
			otherDoc := sample(t, priv, 4)
			doc["signature"].(map[string]any)["value"] = otherDoc["signature"].(map[string]any)["value"]
			return doc
		},
		"coverage changed": func(doc map[string]any) map[string]any {
			doc["content"].(map[string]any)["coverage"].(map[string]any)["merged_prs"] = 1000
			return doc
		},
		"unknown format": func(doc map[string]any) map[string]any {
			doc["format"] = "other"
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
	records(doc)[2].(map[string]any)["actor_login"] = "someone.else"
	if r := Verify(encode(t, sign(t, other, doc["content"].(map[string]any))), nil); r.Verified() {
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
		"# CodeCorvus\nkey_id: " + pub.ID + "\npublic_key: " + b64 + "\n",
		b64 + "\n",
	} {
		k, err := ParsePublicKey([]byte(text))
		if err != nil || k.ID != pub.ID || !k.Key.Equal(pub.Key) {
			t.Errorf("ParsePublicKey(%q) = %+v, %v", text, k, err)
		}
	}
	for _, bad := range []string{"", "public_key: abc", "key_id: ed25519-0000000000000000\npublic_key: " + b64} {
		if _, err := ParsePublicKey([]byte(bad)); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted", bad)
		}
	}
}

// The record hash is computed over the keys the audit trail stores, not over
// the export field names: pin it with a value computed outside Go.
func TestRecordHashKnownAnswer(t *testing.T) {
	r := Record{TenantID: "0192d0a0-0000-7000-8000-0000000000a1", Position: 1, ID: "0192d0a0-0000-7000-8000-000000000001",
		Type: "decisao", ActorLogin: "jane.doe", Data: map[string]string{"tipo": "liberar", "nota": "<&>"},
		At: "2026-07-01T12:00:01.5Z", PreviousHash: Genesis}
	// sha256 of Genesis + "\n" + {"tenant_id":"0192d0a0-0000-7000-8000-0000000000a1","posicao":1,
	// "id":"0192d0a0-0000-7000-8000-000000000001","tipo":"decisao","revisao_id":"","achado_id":"",
	// "ator_usuario_id":"","ator_login":"jane.doe","dados":{"nota":"\u003c\u0026\u003e","tipo":"liberar"},
	// "em":"2026-07-01T12:00:01.5Z"}
	if got, want := RecordHash(r), "4a465c2c387a7a38ac4b8344c3974477c673b170d41ce04a2f78a4aa2c2c1709"; got != want {
		t.Fatalf("RecordHash = %s; want %s", got, want)
	}
}

// An export in another format (e.g. older field names) is rejected, not half read.
func TestVerifyRejectsOtherFieldNames(t *testing.T) {
	priv, pub := newKey(t)
	doc := sample(t, priv, 2)
	doc["conteudo"], doc["content"] = doc["content"], nil
	delete(doc, "content")
	if r := Verify(encode(t, doc), pub); r.Verified() || !strings.Contains(r.Failures[0], "not an evidence export") {
		t.Fatalf("other field names: %+v", r)
	}
}

// The schema shipped in this repository describes this format.
func TestSchemaMatchesFormat(t *testing.T) {
	raw, err := os.ReadFile("schema/evidence-export.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		ID         string `json:"$id"`
		Properties struct {
			Format struct {
				Const string `json:"const"`
			} `json:"format"`
		} `json:"properties"`
		Defs struct {
			Content struct {
				Properties struct {
					Trail struct {
						Properties struct {
							Records struct {
								Items struct {
									Required []string `json:"required"`
								} `json:"items"`
							} `json:"records"`
						} `json:"properties"`
					} `json:"trail"`
				} `json:"properties"`
			} `json:"content"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.ID != "https://codecorvus.com/schemas/evidence-export.v1.json" || s.Properties.Format.Const != Format {
		t.Fatalf("schema $id %q, format %q", s.ID, s.Properties.Format.Const)
	}
	// The record fields in the schema are exactly the ones the verifier reads.
	b, _ := json.Marshal(Record{})
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	required := s.Defs.Content.Properties.Trail.Properties.Records.Items.Required
	if len(required) != len(fields) {
		t.Fatalf("schema record fields %v; verifier reads %d", required, len(fields))
	}
	for _, f := range required {
		if _, ok := fields[f]; !ok {
			t.Errorf("schema record field %q is not read by the verifier", f)
		}
	}
}
