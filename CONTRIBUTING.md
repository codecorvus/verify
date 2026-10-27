# Contributing

Thanks for helping. Issues and pull requests are welcome.

- Keep the tool offline and dependency-free: standard library only, no network, no subprocesses.
- Add a test for every behavior change (`go test ./...`), and run `go vet ./...` before opening a pull request.
- Changes to the verification rules must keep the published format (`schema/evidence-export.v1.json`)
  compatible; a new format gets a new version.
- Security issues: see [SECURITY.md](SECURITY.md), not public issues.

## Developer Certificate of Origin

Every commit must be signed off, certifying that you wrote the change or have the right to submit it under the
project license ([DCO 1.1](https://developercertificate.org/)):

```
git commit -s -m "fix: ..."
```

This adds a `Signed-off-by: Your Name <you@example.com>` line with your real name.
