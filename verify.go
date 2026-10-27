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

// Package verify checks a signed CodeCorvus evidence export (format
// codecorvus.evidence-export.v1) offline, without contacting CodeCorvus:
// the Ed25519 signature over the canonical form of the content, the hash of
// every audit-trail record, the chaining (each record points to the hash of
// the previous one), positions without gaps and the consistency of the totals.
//
// JSON field names follow the published format (schema/evidence-export.v1.json).
package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Format identifies this version of the export format.
const Format = "codecorvus.evidence-export.v1"

// Genesis is the previous hash of each organization's first record.
var Genesis = strings.Repeat("0", 64)

// Document is the exported file. Content stays raw: the signature covers its
// canonical form, recomputed here.
type Document struct {
	Format    string          `json:"format"`
	Content   json.RawMessage `json:"content"`
	Signature Signature       `json:"signature"`
}

// Signature is the block signed by CodeCorvus.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

// Content is what verification reads from the signed content.
type Content struct {
	Format string `json:"format"`
	Org    struct {
		Login    string `json:"login"`
		TenantID string `json:"tenant_id"`
	} `json:"org"`
	Period struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"period"`
	Coverage struct {
		MergedPRs      int64 `json:"merged_prs"`
		ReviewedBefore int64 `json:"reviewed_before_merge"`
		Exceptions     int64 `json:"exceptions"`
		Unjustified    int64 `json:"unjustified"`
	} `json:"coverage"`
	Exceptions []struct {
		Justified bool `json:"justified"`
	} `json:"exceptions"`
	Trail Trail `json:"trail"`
}

// Trail is the exported contiguous slice of the chain.
type Trail struct {
	FromPosition int64    `json:"from_position"`
	ToPosition   int64    `json:"to_position"`
	Total        int64    `json:"total"`
	PreviousHash string   `json:"previous_hash"`
	LastHash     string   `json:"last_hash"`
	Records      []Record `json:"records"`
}

// Record is an audit-trail event as CodeCorvus stores it.
type Record struct {
	TenantID     string            `json:"tenant_id"`
	Position     int64             `json:"position"`
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	ReviewID     string            `json:"review_id"`
	FindingID    string            `json:"finding_id"`
	ActorUserID  string            `json:"actor_user_id"`
	ActorLogin   string            `json:"actor_login"`
	Data         map[string]string `json:"data"`
	At           string            `json:"at"`
	PreviousHash string            `json:"previous_hash"`
	Hash         string            `json:"hash"`
}

// hashed is the form of the record that goes into the hash: these fields, in
// this order, encoded by Go's encoding/json (data keys sorted; <, > and &
// escaped as \u003c, \u003e and \u0026). The JSON keys are fixed by the format
// and differ from the export field names on purpose: they are the keys under
// which the audit trail hashes each record when it is written, so every
// record, including those written before this format, stays verifiable.
type hashed struct {
	TenantID    string            `json:"tenant_id"`
	Position    int64             `json:"posicao"`
	ID          string            `json:"id"`
	Type        string            `json:"tipo"`
	ReviewID    string            `json:"revisao_id"`
	FindingID   string            `json:"achado_id"`
	ActorUserID string            `json:"ator_usuario_id"`
	ActorLogin  string            `json:"ator_login"`
	Data        map[string]string `json:"dados"`
	At          string            `json:"em"`
}

// RecordHash is hex(sha256(previous_hash + "\n" + record JSON)).
func RecordHash(r Record) string {
	data := r.Data
	if data == nil {
		data = map[string]string{}
	}
	body, _ := json.Marshal(hashed{TenantID: r.TenantID, Position: r.Position, ID: r.ID, Type: r.Type,
		ReviewID: r.ReviewID, FindingID: r.FindingID, ActorUserID: r.ActorUserID, ActorLogin: r.ActorLogin,
		Data: data, At: r.At})
	h := sha256.New()
	h.Write([]byte(r.PreviousHash))
	h.Write([]byte{'\n'})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// PublicKey is the key published at /.well-known/codecorvus-evidence.pub.
type PublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

// KeyID is "ed25519-" plus the first 16 hex digits of the sha256 of the public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(h[:])[:16]
}

// ParsePublicKey accepts the file served by the public route (lines
// "key_id: …" and "public_key: …"; lines starting with # are comments) or just
// the base64 key.
func ParsePublicKey(text []byte) (PublicKey, error) {
	var k PublicKey
	var b64 string
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "key_id:"):
			k.ID = strings.TrimSpace(strings.TrimPrefix(line, "key_id:"))
		case strings.HasPrefix(line, "public_key:"):
			b64 = strings.TrimSpace(strings.TrimPrefix(line, "public_key:"))
		case b64 == "" && !strings.Contains(line, ":"):
			b64 = line
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return k, errors.New("public key: expected 32 bytes in base64")
	}
	k.Key = ed25519.PublicKey(raw)
	if k.ID == "" {
		k.ID = KeyID(k.Key)
	}
	if k.ID != KeyID(k.Key) {
		return k, fmt.Errorf("public key: key id %s does not match the key", k.ID)
	}
	return k, nil
}

// Result is what verification found. No failures = verified.
type Result struct {
	Org          string
	Period       string
	KeyID        string
	ExternalKey  bool // checked against the given key (not only the file's own)
	Records      int
	FromPosition int64
	ToPosition   int64
	LastHash     string
	Exceptions   int
	Failures     []string
	Warnings     []string
}

// Verified reports whether nothing failed.
func (r Result) Verified() bool { return len(r.Failures) == 0 }

func (r *Result) fail(format string, args ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
}

// Verify checks the file. With a key, the signature must be from that key;
// without one, the file's own public key is used and the result warns that
// authorship is only proven by comparing the key id with the published one.
func Verify(file []byte, key *PublicKey) Result {
	var res Result
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(file))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		res.fail("not an evidence export: %v", err)
		return res
	}
	if doc.Format != Format {
		res.fail("unknown format %q; expected %s", doc.Format, Format)
		return res
	}
	verifySignature(&res, doc, key)

	var c Content
	if err := json.Unmarshal(doc.Content, &c); err != nil {
		res.fail("unreadable content: %v", err)
		return res
	}
	if c.Format != Format {
		res.fail("format of the signed content (%q) differs from the file", c.Format)
	}
	res.Org, res.Period = c.Org.Login, c.Period.From+" to "+c.Period.To
	verifyTrail(&res, c.Org.TenantID, c.Trail)

	res.Exceptions = len(c.Exceptions)
	notJustified := int64(0)
	for _, e := range c.Exceptions {
		if !e.Justified {
			notJustified++
		}
	}
	if c.Coverage.Exceptions != int64(len(c.Exceptions)) || c.Coverage.Unjustified != notJustified {
		res.fail("coverage says %d exceptions (%d not justified), the list has %d (%d)", c.Coverage.Exceptions,
			c.Coverage.Unjustified, len(c.Exceptions), notJustified)
	}
	if c.Coverage.ReviewedBefore > c.Coverage.MergedPRs {
		res.fail("reviewed before merge (%d) exceeds merged PRs (%d)", c.Coverage.ReviewedBefore, c.Coverage.MergedPRs)
	}
	return res
}

func verifySignature(res *Result, doc Document, key *PublicKey) {
	s := doc.Signature
	res.KeyID = s.KeyID
	if s.Algorithm != "Ed25519" {
		res.fail("signature algorithm %q; expected Ed25519", s.Algorithm)
		return
	}
	pub, err := base64.StdEncoding.DecodeString(s.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		res.fail("invalid public key in the file")
		return
	}
	if s.KeyID != KeyID(pub) {
		res.fail("key id %s does not match the file's public key", s.KeyID)
		return
	}
	if key != nil {
		if key.ID != s.KeyID || !key.Key.Equal(ed25519.PublicKey(pub)) {
			res.fail("signed with key %s, not with the given key (%s)", s.KeyID, key.ID)
			return
		}
		res.ExternalKey = true
	} else {
		res.Warnings = append(res.Warnings, fmt.Sprintf("signature checked with the file's own key (%s); "+
			"to prove authorship, run with --key and the key published at /.well-known/codecorvus-evidence.pub", s.KeyID))
	}
	sig, err := base64.StdEncoding.DecodeString(s.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		res.fail("invalid signature value")
		return
	}
	canon, err := Canonical(doc.Content)
	if err != nil {
		res.fail("content is not in canonical form: %v", err)
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canon, sig) {
		res.fail("signature does not match: the content was changed or the signature belongs to another file")
	}
}

func verifyTrail(res *Result, tenant string, t Trail) {
	rs := t.Records
	res.Records, res.FromPosition, res.ToPosition, res.LastHash = len(rs), t.FromPosition, t.ToPosition, t.LastHash
	if t.Total != int64(len(rs)) {
		res.fail("trail says %d records, the file has %d", t.Total, len(rs))
	}
	if len(rs) == 0 {
		if t.FromPosition != 0 || t.ToPosition != 0 {
			res.fail("trail without records but with positions %d–%d", t.FromPosition, t.ToPosition)
		}
		return
	}
	if t.FromPosition < 1 || t.ToPosition-t.FromPosition+1 != int64(len(rs)) {
		res.fail("positions %d–%d do not fit %d records", t.FromPosition, t.ToPosition, len(rs))
	}
	if t.FromPosition == 1 && t.PreviousHash != Genesis {
		res.fail("the first record of the chain must start from the genesis hash")
	}
	previous := t.PreviousHash
	for i, r := range rs {
		expected := t.FromPosition + int64(i)
		switch {
		case r.Position != expected:
			res.fail("record %d: position %d; expected %d (gap or reordering)", i+1, r.Position, expected)
		case r.TenantID != tenant:
			res.fail("record at position %d belongs to another organization", r.Position)
		}
		if r.PreviousHash != previous {
			res.fail("position %d: previous hash is not the hash of the previous record (record removed, inserted or reordered)",
				r.Position)
		}
		if RecordHash(r) != r.Hash {
			res.fail("position %d: hash does not match the record content (record changed)", r.Position)
		}
		previous = r.Hash
	}
	if last := rs[len(rs)-1]; last.Hash != t.LastHash || last.Position != t.ToPosition {
		res.fail("last record (position %d) is not the declared one (position %d)", last.Position, t.ToPosition)
	}
}
