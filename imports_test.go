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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The verifier does not talk to the network, does not execute anything and
// only uses the standard library: check the imports of every file in the
// module, and the license header.
func TestNoNetwork(t *testing.T) {
	forbidden := []string{"net", "os/exec", "plugin", "unsafe", "syscall"}
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			return err
		}
		if len(f.Comments) == 0 || !strings.Contains(f.Comments[0].Text(), "SPDX-License-Identifier: Apache-2.0") {
			t.Errorf("%s has no Apache-2.0 header", path)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first := strings.Split(p, "/")[0]
			if strings.Contains(first, ".") && p != "github.com/codecorvus/verify" &&
				!strings.HasPrefix(p, "github.com/codecorvus/verify/") {
				t.Errorf("%s imports %s, outside the standard library", path, p)
			}
			for _, x := range forbidden {
				if p == x || strings.HasPrefix(p, x+"/") {
					t.Errorf("%s imports %s", path, p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
