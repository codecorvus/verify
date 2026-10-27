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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Canonical returns the canonical form of a JSON value, which the signature
// covers (schema evidence-export.v1):
//
//   - no whitespace outside strings;
//   - object keys sorted by their UTF-8 bytes, no duplicates;
//   - integers only, in minimal decimal form (no plus sign, leading zeros,
//     fraction or exponent);
//   - strings in valid UTF-8, escaping only the quote, the backslash and
//     control characters (U+0000 to U+001F: \b \t \n \f \r, the others as
//     lowercase \u00xx); everything else is written literally.
//
// Input outside these rules (fractional number, duplicate key, invalid UTF-8,
// trailing data) is an error: the verifier does not guess.
func Canonical(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("canonical: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out bytes.Buffer
	if err := writeValue(dec, &out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("canonical: trailing data after the value")
	}
	return out.Bytes(), nil
}

var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func writeValue(dec *json.Decoder, out *bytes.Buffer) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("canonical: %w", err)
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return writeObject(dec, out)
		case '[':
			return writeArray(dec, out)
		}
		return fmt.Errorf("canonical: unexpected delimiter %q", v)
	case string:
		writeString(out, v)
	case json.Number:
		s := v.String()
		if !integer.MatchString(s) || s == "-0" {
			return fmt.Errorf("canonical: number %q is not a minimal integer", s)
		}
		out.WriteString(s)
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("canonical: unexpected token %T", tok)
	}
	return nil
}

func writeObject(dec *json.Decoder, out *bytes.Buffer) error {
	members := map[string][]byte{}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("canonical: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("canonical: object key is not a string")
		}
		if _, dup := members[key]; dup {
			return fmt.Errorf("canonical: duplicate key %q", key)
		}
		var value bytes.Buffer
		if err := writeValue(dec, &value); err != nil {
			return err
		}
		members[key] = value.Bytes()
		keys = append(keys, key)
	}
	if _, err := dec.Token(); err != nil { // '}'
		return fmt.Errorf("canonical: %w", err)
	}
	sort.Strings(keys) // Go compares strings byte by byte: UTF-8 byte order
	out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		writeString(out, k)
		out.WriteByte(':')
		out.Write(members[k])
	}
	out.WriteByte('}')
	return nil
}

func writeArray(dec *json.Decoder, out *bytes.Buffer) error {
	out.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := writeValue(dec, out); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // ']'
		return fmt.Errorf("canonical: %w", err)
	}
	out.WriteByte(']')
	return nil
}

func writeString(out *bytes.Buffer, s string) {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	out.WriteString(b.String())
}
