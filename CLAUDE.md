# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

`uccellino` is a Go CLI / automation layer for the CrowdStrike Falcon API, meant to
be used interactively or inside CI/CD pipelines. Today only IOC (indicator of
compromise) management is implemented; endpoint management, threat intel and CSPM
are planned (see the checklist in `README.md`).

Module path: `github.com/mattiazi/uccellino` — Go 1.25.7.

## Commands

```bash
go build ./...                 # build everything
go build -o uccellino ./cmd/uccellino
go test ./...                  # run all tests (only cli/ has tests today)
go test ./cli -run TestName -v # single test
go vet ./...
gofmt -l .                     # must print nothing
```

There is no Makefile, no linter config and no CI workflow in the repo — `go build`,
`go vet`, `gofmt` and `go test` are the full check set.

## Layout

```
cmd/uccellino/main.go      thin entrypoint: calls cli.Execute(), prints error, exit 1
cli/root.go                all cobra wiring, flag parsing, output formatting
cli/root_test.go           CLI tests driven through a fake IOCsAPI
internal/config/config.go  env-var loading + validation + redacted printing
pkg/uccellino/ioc/         domain layer: IOC struct, IOCsAPI interface, validation
pkg/falconwrap/            adapter layer: gofalcon SDK client + IOCsAPI implementation
```

### Architecture rule

The domain package (`pkg/uccellino/...`) must stay free of vendor SDK types. All
`gofalcon` imports, request/response models and field mapping belong in
`pkg/falconwrap` — this is stated in the comment on `IOCsAPI` and on `IOCAdapter`,
keep it that way. `cli` talks to the domain interface only, never to gofalcon
directly (except `falcon.CloudValidate` for parsing the `--cloud` flag).

New capability = new domain package under `pkg/uccellino/<thing>/` (types +
interface + validation), new adapter in `pkg/falconwrap/<thing>_adapter.go`, new
cobra subcommand in `cli/`.

## Configuration

Credentials come from env vars, read in `internal/config`:

- `CROWDSTRIKE_CLIENT_ID` (required)
- `CROWDSTRIKE_CLIENT_SECRET` (required)
- `CROWDSTRIKE_CLOUD` (optional; defaults to autodiscover)

Persistent flags `--client-id`, `--client-secret`, `--cloud` override the env vars.
`--output` selects `text` (default) or `json`.

`config.LoadRaw()` loads without checking required fields; `config.Validate()` does
the checking; `config.Load()` does both. The CLI uses `LoadRaw` + flag overrides +
`Validate` so flags can supply what the env is missing.

Never print secrets — `Config.RedactedString()` exists for that.

## CLI conventions

- Commands are built by `newRootCmdWithDeps(dependencies{out, errOut, provider})`.
  `NewRootCmd()` is the production wiring; tests call `newRootCmdWithDeps` with a
  fake `iocProvider` so no network is touched. Keep new commands testable the same
  way: no direct `os.Stdout` writes, use `cmd.OutOrStdout()`.
- Credentials are resolved lazily in `rootState.ensureIOCAPI`, invoked from
  `PersistentPreRunE`. Help output must never require credentials — the
  `isHelpCommand` / `cmd == iocCmd` guard exists for that and is covered by tests.
- Root uses `SilenceUsage` + `SilenceErrors`; errors are returned up and printed
  once by `main`. Return errors, don't `os.Exit` inside commands.
- Every subcommand sets `Args` (`cobra.NoArgs` / `cobra.ExactArgs`) and a `Long`
  description listing the valid option values. Tests assert on those help snippets,
  so update `cli/root_test.go` when changing the wording.
- Output formatting goes through `writeIOCList` / `writeStatus` / `writeJSON`, which
  re-validate the mode. Text output is the `key=value` line format asserted in tests.

## Domain notes

- `ioc.ValidateCreate` is called both in the CLI (before hitting the API) and again
  inside `IOCAdapter.Create`. Keep both call sites.
- Validation is deliberately minimal: it rejects `prevent` / `allow` /
  `prevent_no_ui` for `domain`, `ipv4`, `ipv6`. Type and action strings are not
  otherwise checked against an allowlist, so unknown values reach the API.
- The `IOC` struct comments and the CLI help disagree slightly on supported types
  (`ip` vs `ipv4`); the CLI help text is the intended contract.

## Known rough edges

Do not "tidy" these away silently — they are real bugs worth fixing deliberately,
with tests:

- `IOCAdapter.List` ignores its `filter` argument and the `a.fc` client it was
  constructed with: it calls `config.Load()` and builds a fresh client itself, using
  `context.Background()` instead of the passed `ctx`. The `--filter` flag therefore
  has no effect today.
- `--limit` on `ioc list` is parsed but unused (the check is commented out in
  `cli/root.go`); `List` always pages with a hardcoded limit of 2000.
- `pkg/uccellino/ioc/ioc.go` is an empty package declaration.
- Only `cli/` has tests. Adapter and config packages are untested.

## Git

Work on the branch you were assigned, commit with descriptive messages, and push
with `git push -u origin <branch>`.
