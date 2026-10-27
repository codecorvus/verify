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
	content := []byte(`{"format":"` + verify.Format + `","org":{"login":"example-org","tenant_id":"t"},` +
		`"period":{"from":"2026-07-01","to":"2026-09-30"},"coverage":{"merged_prs":0,"reviewed_before_merge":0,` +
		`"exceptions":0,"unjustified":0},"exceptions":[],"trail":{"from_position":0,"to_position":0,"total":0,` +
		`"previous_hash":"","last_hash":"","records":[]}}`)
	canon, err := verify.Canonical(content)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := json.Marshal(map[string]any{"format": verify.Format, "content": json.RawMessage(content),
		"signature": map[string]string{"algorithm": "Ed25519", "key_id": verify.KeyID(pk),
			"public_key": base64.StdEncoding.EncodeToString(pk),
			"value":      base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))}})
	dir := t.TempDir()
	doc, pub = filepath.Join(dir, "export.json"), filepath.Join(dir, "codecorvus-evidence.pub")
	if err := os.WriteFile(doc, d, 0o600); err != nil {
		t.Fatal(err)
	}
	text := "key_id: " + verify.KeyID(pk) + "\npublic_key: " + base64.StdEncoding.EncodeToString(pk) + "\n"
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
	_ = os.WriteFile(tampered, bytes.Replace(raw, []byte(`"merged_prs":0`), []byte(`"merged_prs":1`), 1), 0o600)
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
