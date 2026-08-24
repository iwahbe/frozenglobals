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
unexported package-level functions that are only ever statically called from
init-time code, and anonymous functions nested in any of those whose closure
value does not outlive initialization):

1. **Mutation** — any write whose target storage is reachable from a global,
   chased through field/index projections and loads:
   - `g = v`, `g.Field = v`, `g[i] = v`, `g[k] = v`, `*g = v`
   - writes through pointers, slices, and maps read out of a global
     (`ptr.Field = v` where `var ptr = &T{}`)
   - passing a global-aliasing pointer, map, or slice into a callee position
     the callee is known to write through: a same-package function that
     provably mutates that parameter (`helper(ptr)` where `helper` assigns
     through it, computed transitively), a [known mutator](#known-mutators)
     (`json.Unmarshal(b, ptr)`, `sort.Strings(words)`, `delete(m, k)`), or a
     function annotated with `//frozenglobals:mutator`
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

- **Init-time closures passed onward.** A closure created during init is
  treated as post-init when its value visibly outlives initialization —
  stored into global-reachable storage, returned, or started as a goroutine.
  A closure that merely flows through an intermediary (passed as a call
  argument to a callee that stashes it, or laundered through a local
  variable's phi or an interface conversion before being stored) is still
  treated as init-time. (Chasing arguments would flag the pervasive
  `forEach`-style callback pattern inside `init`.)
- **Loaded values passed to unknown functions are not tracked.**
  `theirpkg.Fill(p)` where `p` was read out of a global can mutate global
  state undetected when `theirpkg.Fill` is not a same-package function, a
  known mutator, or annotated — flagging every `fmt.Println(cfg)` would drown
  the signal, so unknown callees are assumed read-only. Extend coverage with
  the [known-mutators configuration](#known-mutators).
- **Channels.** Sends on globally-stored channels are not reported.
- `unsafe` laundering defeats the analysis (the initial conversion is caught
  by the escape check; what happens after is not).

## Known mutators

Same-package callees are summarized automatically: a function that provably
writes through a reference-carrying parameter (directly, or by passing it
onward into another mutated position) marks that argument position as
mutating. For callees the analysis cannot see through, a curated list covers
standard-library functions whose purpose is to mutate an argument, including:

- the `append`, `clear`, `copy`, and `delete` builtins
- decoding into an out-parameter: `encoding/json.Unmarshal` and
  `(*json.Decoder).Decode` (likewise `xml`, `gob`, `asn1`, `binary`)
- the `fmt` scanning family (`Sscan`, `Fscanf`, …) and
  `(*database/sql.Rows).Scan`
- in-place reordering: `sort.*`, `slices.Sort`/`Reverse`/`Delete`/…,
  `maps.Copy`/`DeleteFunc`/`Insert`, `container/heap`
- buffer filling: `(io.Reader).Read`, `io.ReadFull`, `crypto/rand.Read`
- all of `sync/atomic`'s pointer-argument functions

Two extension mechanisms:

1. **Configuration.** The `-mutators` flag takes comma-separated
   fully-qualified functions, each treated as writing through every
   parameter:

   ```sh
   frozenglobals -mutators='github.com/you/db.Hydrate,(*github.com/you/pb.Buf).Merge' ./...
   ```

   Under golangci-lint, the same list goes in the linter settings:

   ```yaml
   settings:
     custom:
       frozenglobals:
         type: module
         settings:
           mutators:
             - github.com/you/db.Hydrate
   ```

2. **Annotation.** A package can declare its own mutators with a doc-comment
   directive, exported as an analysis fact so importing packages see it.
   The bare form marks every parameter; the argument form names the mutated
   parameters:

   ```go
   //frozenglobals:mutator dst
   func Hydrate(dst any, row Row) { ... }
   ```

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
- Call arguments that chase to a global root (interface conversions
  unwrapped, loads allowed) and land in a callee position the mutator index
  marks as written-through → **mutation**. The index combines least-fixpoint
  parameter summaries of same-package functions, the known-mutators list, and
  imported `//frozenglobals:mutator` facts.
- Every instruction operand that is a pure address chain rooted at a global
  (no load crossing) and is not in a sanctioned position (load source,
  further projection, store target) → **escape**.

Init detection: SSA names the synthetic package initializer `init` and
source-level init functions `init#1`, `init#2`, …; anything lexically nested
in one of those counts. On top of that lexical seed, an unexported
package-level function counts as init-time when its every reference in the
package is a static call (or defer) from an init-time function, and an
anonymous function counts when its enclosing function is init-time and its
closure value does not escape (stored into global-reachable storage,
returned, or started with `go`) — computed as a greatest fixpoint, so
transitive and mutually recursive init helpers qualify. Exported functions
(callable from other packages), methods (reachable through interfaces),
named functions used as values, and functions launched with `go` never
qualify.

## Development

```sh
go test ./...   # analysistest against testdata/src/{a,b}
```
