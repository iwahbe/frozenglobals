// Package frozenglobals defines an analyzer that permits package-level
// variables but forbids mutating them after package initialization.
//
// A global written only during package initialization (initializer
// expressions and init functions) is treated as a constant and allowed:
//
//	var version string                   // set via -ldflags
//	var DefaultRetry = RetryPolicy{...}  // constant-shaped configuration
//
// Any write reachable after initialization is reported:
//
//   - direct assignment: g = v, g.Field = v, g[i] = v, g[k] = v, *g = v
//   - writes through values loaded from a global (pointers, slices, maps)
//
// Additionally, letting the address of a global escape outside of
// initialization (passing &g to a call, storing it, returning it, calling a
// pointer-receiver method on it) is reported, because mutation can no longer
// be ruled out statically.
//
// Known, intentional gaps (see README): interior mutation through values that
// are passed to other functions, closures created during init but invoked
// later, and goroutines spawned from init.
package frozenglobals

import (
	"fmt"
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// Analyzer reports mutation of package-level variables outside of package
// initialization.
var Analyzer = &analysis.Analyzer{
	Name:     "frozenglobals",
	Doc:      "reports mutation of package-level variables outside of package initialization",
	URL:      "https://github.com/iwahbe/frozenglobals",
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	s := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	for _, fn := range s.SrcFuncs {
		if initTime(fn) {
			continue
		}
		checkFunction(pass, fn)
	}
	return nil, nil
}

// initTime reports whether fn runs as part of package initialization: the
// synthetic package initializer, a source-level init function (which SSA
// names "init#1", "init#2", ...), or an anonymous function nested in one.
//
// Anonymous functions nested in init are assumed to run at init time. A
// closure that init stores for later execution defeats this assumption; that
// gap is documented rather than closed, because closing it would flag the
// common `func init() { ... immediate helper closures ... }` pattern.
func initTime(fn *ssa.Function) bool {
	for f := fn; f != nil; f = f.Parent() {
		if f.Signature.Recv() != nil {
			return false // a method named init is not an init function
		}
		if name := f.Name(); name == "init" || strings.HasPrefix(name, "init#") {
			return true
		}
	}
	return false
}

func checkFunction(pass *analysis.Pass, fn *ssa.Function) {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			checkInstruction(pass, instr)
		}
	}
}

func checkInstruction(pass *analysis.Pass, instr ssa.Instruction) {
	// 1. Writes. Chase the written address back through address projections
	// (&g.F, &g[i]) and loads of reference values (pointers, slices, maps
	// read out of a global) to a *ssa.Global root.
	switch t := instr.(type) {
	case *ssa.Store:
		if g := storageRoot(t.Addr); g != nil {
			reportMutation(pass, instr.Pos(), g)
		}
	case *ssa.MapUpdate:
		if g := storageRoot(t.Map); g != nil {
			reportMutation(pass, instr.Pos(), g)
		}
	}

	// 2. Escapes. Any use of an address rooted at a global, other than the
	// sanctioned read/projection/write positions handled above, hands out an
	// alias under which future mutation cannot be ruled out.
	rands := instr.Operands(nil)
	for _, rand := range rands {
		v := *rand
		if v == nil {
			continue
		}
		g := addressRoot(v)
		if g == nil {
			continue
		}
		if sanctionedUse(instr, v) {
			continue
		}
		pos := instr.Pos()
		if pos == token.NoPos {
			pos = v.Pos()
		}
		pass.Report(analysis.Diagnostic{
			Pos: pos,
			Message: fmt.Sprintf(
				"address of %s escapes: mutation outside of package initialization cannot be ruled out",
				relName(pass, g)),
		})
	}
}

func reportMutation(pass *analysis.Pass, pos token.Pos, g *ssa.Global) {
	pass.Report(analysis.Diagnostic{
		Pos: pos,
		Message: fmt.Sprintf(
			"%s is mutated outside of package initialization",
			relName(pass, g)),
	})
}

// storageRoot returns the global whose storage v points into (or aliases), if
// any. It follows address projections and loads: a pointer, slice, or map
// loaded out of a global still refers to storage reachable from that global,
// so a write through it is a write to global state.
func storageRoot(v ssa.Value) *ssa.Global {
	for {
		switch t := v.(type) {
		case *ssa.Global:
			return t
		case *ssa.FieldAddr:
			v = t.X
		case *ssa.IndexAddr:
			v = t.X
		case *ssa.Slice:
			v = t.X
		case *ssa.UnOp:
			if t.Op != token.MUL {
				return nil
			}
			v = t.X // load: chase the location the value was read from
		default:
			return nil
		}
	}
}

// addressRoot is storageRoot restricted to pure address chains: it does not
// cross loads. It answers "is v the address of (part of) a global?", which is
// the question that matters for escape detection. Values *loaded from*
// globals are deliberately excluded — passing a loaded map or pointer to a
// function is unverifiable but pervasive (fmt.Println, errors.Is, value
// method calls), and flagging it would drown the signal.
func addressRoot(v ssa.Value) *ssa.Global {
	for {
		switch t := v.(type) {
		case *ssa.Global:
			return t
		case *ssa.FieldAddr:
			v = t.X
		case *ssa.IndexAddr:
			v = t.X
		case *ssa.Slice:
			v = t.X
		default:
			return nil
		}
	}
}

// sanctionedUse reports whether instr's use of the global-rooted address v is
// one of the closed set of operations that either only reads through the
// address or is separately checked as a write.
func sanctionedUse(instr ssa.Instruction, v ssa.Value) bool {
	switch t := instr.(type) {
	case *ssa.UnOp:
		return t.Op == token.MUL && t.X == v // load (read)
	case *ssa.FieldAddr:
		return t.X == v // projection; its uses are checked in turn
	case *ssa.IndexAddr:
		return t.X == v
	case *ssa.Slice:
		return t.X == v
	case *ssa.Store:
		// Writing *to* the address is reported as a mutation above; storing
		// the address itself somewhere (t.Val == v) is an escape.
		return t.Addr == v
	case *ssa.MapUpdate:
		return false // an address used as map key/value escapes
	case *ssa.DebugRef:
		return true
	default:
		return false
	}
}

func relName(pass *analysis.Pass, g *ssa.Global) string {
	return g.RelString(pass.Pkg)
}
