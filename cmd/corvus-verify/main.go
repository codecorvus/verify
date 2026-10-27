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

// corvus-verify checks a CodeCorvus evidence export offline, without
// contacting CodeCorvus.
//
//	corvus-verify <export.json> [--key <codecorvus-evidence.pub>]
//
// Exit status 0: verified; 1: not verified; 2: usage error or unreadable file.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/codecorvus/verify"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = "usage: corvus-verify <export.json> [--key <codecorvus-evidence.pub>]"

func run(args []string, stdout, stderr io.Writer) int {
	var file, keyFile string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--key" || a == "-key":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, usage)
				return 2
			}
			i++
			keyFile = args[i]
		case a == "-h" || a == "--help":
			fmt.Fprintln(stdout, usage)
			return 0
		case file == "":
			file = a
		default:
			fmt.Fprintln(stderr, usage)
			return 2
		}
	}
	if file == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	raw, err := os.ReadFile(file) // #nosec G304 -- the file to verify is chosen by whoever runs the tool
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var key *verify.PublicKey
	if keyFile != "" {
		text, err := os.ReadFile(keyFile) // #nosec G304 -- likewise, the public key chosen by whoever runs the tool
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		k, err := verify.ParsePublicKey(text)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		key = &k
	}

	r := verify.Verify(raw, key)
	fmt.Fprintf(stdout, "org: %s · period: %s\n", r.Org, r.Period)
	fmt.Fprintf(stdout, "trail: %d records, positions %d–%d, last hash %s\n", r.Records, r.FromPosition, r.ToPosition,
		r.LastHash)
	fmt.Fprintf(stdout, "exceptions: %d\n", r.Exceptions)
	for _, w := range r.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	if !r.Verified() {
		for _, f := range r.Failures {
			fmt.Fprintln(stdout, "FAILED:", f)
		}
		fmt.Fprintln(stdout, "result: NOT VERIFIED")
		return 1
	}
	source := "embedded in the file"
	if r.ExternalKey {
		source = "given with --key"
	}
	fmt.Fprintf(stdout, "ok: Ed25519 signature by key %s (%s), record hashes, chaining and gap-free positions\n",
		r.KeyID, source)
	fmt.Fprintln(stdout, "result: VERIFIED")
	return 0
}
