# frozenglobals

A Go analyzer that permits package-level variables but forbids **mutating them
after package initialization**. Globals used like constants are fine; globals
used as mutable state are not.

```go
var version string                  // OK: written only by the linker
var DefaultRetry = Policy{Max: 3}   // OK: constant-shaped value that `const` can't express

func init() { registry["json"] = jsonCodec } // OK: init-time write

func Register(name string, c Codec) {
	registry[name] = c // reported: registry is mutated outside of package initialization
}
```

## Why not an existing linter?

- [`gochecknoglobals`](https://github.com/leighmcculloch/gochecknoglobals) is
  declaration-based: it flags every global that doesn't match a hardcoded
  name/pattern allowlist, so `var DefaultRetry = Policy{Max: 3}` is rejected
  even though it is never written after init.
- [`reassign`](https://github.com/curioswitch/go-reassign) is mutation-based
  but only checks direct reassignment of *another* package's globals.

`frozenglobals` checks what actually matters: **writes**, wherever they occur,
with package initialization as the only sanctioned write window.

## What is reported

Outside of package initialization (initializer expressions, `init` functions,
and anonymous functions nested in them):

1. **Mutation** — any write whose target storage is reachable from a global,
   chased through field/index projections and loads:
   - `g = v`, `g.Field = v`, `g[i] = v`, `g[k] = v`, `*g = v`
   - writes through pointers, slices, and maps read out of a global
     (`ptr.Field = v` where `var ptr = &T{}`)
2. **Escape** — the address of (part of) a global handed out as a value, under
   which mutation can no longer be ruled out statically:
   - `f(&g)`, `sink = &g`, `return &g`
   - pointer-receiver method calls on a global (`mu.Lock()` where
     `var mu sync.Mutex` — a mutable global by design, which is the point)

Reads are never reported: value copies, map/slice indexing, value-receiver
method calls, `errors.Is(err, ErrSentinel)`, etc.

Mutation of *other* packages' globals is reported too (`io.EOF = nil`
qualifies as `io.EOF is mutated outside of package initialization`), which
subsumes `reassign`.

## Known gaps (by design)

The analysis is intraprocedural and syntactic about writes; the escape check
is what keeps it honest. Remaining holes, accepted to keep the
signal-to-noise ratio high:

- **Init-time closures run later.** A closure created inside `init` is
  treated as init-time even if `init` stores it and something calls it after
  initialization. (Closing this would flag the pervasive immediate-helper
  pattern inside `init`.)
- **Helpers called from init are not init.** Writes are attributed to the
  lexical function, not the call graph, so a named function that mutates a
  global is flagged even when it is only ever called from `init`. Inline the
  write into `init`, or annotate the call site with
  `//nolint:frozenglobals`.
- **Loaded values passed onward are not tracked.** `json.Unmarshal(b, p)`
  where `p` was read out of a global can mutate global state undetected. Only
  passing `&global` itself is flagged; passing values *loaded from* globals is
  not, because flagging every `fmt.Println(cfg)` would drown the signal.
- **Channels.** Sends on globally-stored channels are not reported.
- `unsafe` laundering defeats the analysis (the initial conversion is caught
  by the escape check; what happens after is not).

## Standalone usage

```sh
go install github.com/iwahbe/frozenglobals/cmd/frozenglobals@latest
frozenglobals ./...
```

## golangci-lint (custom binary, module plugin)

Requires golangci-lint v2 built via the [module plugin
system](https://golangci-lint.run/plugins/module-plugins/).

`.custom-gcl.yml`:

```yaml
version: v2.4.0 # your golangci-lint version
plugins:
  - module: 'github.com/iwahbe/frozenglobals'
    version: v0.1.0
```

`.golangci.yml`:

```yaml
version: "2"
linters:
  enable:
    - frozenglobals
  settings:
    custom:
      frozenglobals:
        type: module
        description: Forbids mutating package-level variables after package initialization.
```

Then build and run the custom binary:

```sh
golangci-lint custom   # produces ./custom-gcl
./custom-gcl run ./...
```

To allow mutation in tests, use a standard exclusion rule instead of a linter
option:

```yaml
linters:
  exclusions:
    rules:
      - path: _test\.go
        linters: [frozenglobals]
```

## Implementation

Built on `golang.org/x/tools/go/analysis` with the `buildssa` pass. For every
function that is not (nested in) an init function:

- `Store` and `MapUpdate` instructions are chased back through
  `FieldAddr`/`IndexAddr`/`Slice` projections and loads to an `*ssa.Global`
  root → **mutation**.
- Every instruction operand that is a pure address chain rooted at a global
  (no load crossing) and is not in a sanctioned position (load source,
  further projection, store target) → **escape**.

Init detection: SSA names the synthetic package initializer `init` and
source-level init functions `init#1`, `init#2`, …; anything lexically nested
in one of those counts.

## Development

```sh
go test ./...   # analysistest against testdata/src/{a,b}
```
