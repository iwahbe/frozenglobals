// Package frozenglobals defines an analyzer that permits package-level
// variables but forbids mutating them after package initialization.
//
// A global written only during package initialization (initializer
// expressions, init functions, and unexported helpers only reachable from
// them) is treated as a constant and allowed:
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
// Passing a global-aliasing pointer, map, or slice into a callee position the
// callee is known to write through is reported as a mutation too: same-package
// callees are summarized by analysis, and callees the analysis cannot see
// through are covered by a curated known-mutators list (extensible with the
// -mutators flag) and by //frozenglobals:mutator doc-comment annotations,
// which are exported as facts for importing packages.
//
// Known, intentional gaps (see README): interior mutation through values
// passed to unknown functions, channel receives, aliases laundered through
// projections of local heap storage, and init-time closures that reach
// post-init execution through an intermediary (passed as a call argument, or
// laundered through a phi or interface conversion) rather than being stored,
// returned, or started as a goroutine directly.
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
	Name:      "frozenglobals",
	Doc:       "reports mutation of package-level variables outside of package initialization",
	URL:       "https://github.com/iwahbe/frozenglobals",
	Requires:  []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes: []analysis.Fact{(*mutatorFact)(nil)},
	Run:       run,
}

// mutatorsFlag extends the known-mutators list: comma-separated
// fully-qualified functions (types.Func.FullName form), each treated as
// writing through every parameter.
var mutatorsFlag string

func init() {
	Analyzer.Flags.StringVar(&mutatorsFlag, "mutators", "",
		"comma-separated fully-qualified functions to treat as mutating their parameters, "+
			`e.g. "encoding/json.Unmarshal,(*encoding/json.Decoder).Decode"`)
}

func run(pass *analysis.Pass) (any, error) {
	s := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	var extra []string
	if mutatorsFlag != "" {
		extra = strings.Split(mutatorsFlag, ",")
	}
	m, err := newMutatorIndex(pass, extra)
	if err != nil {
		return nil, err
	}
	fns := packageFuncs(s)
	initFns := initTimeFuncs(fns)
	collectDirectives(pass, s.Pkg.Prog, m)
	paramMutators(m, fns)
	for _, fn := range fns {
		if initFns[fn] {
			continue
		}
		checkFunction(pass, fn, m)
	}
	return nil, nil
}

// packageFuncs returns every function in the package with a body to analyze:
// buildssa's source functions plus the synthetic package initializer (which
// holds global initializer expressions) and the anonymous functions nested in
// it, which buildssa does not include in SrcFuncs.
func packageFuncs(s *buildssa.SSA) []*ssa.Function {
	fns := make([]*ssa.Function, 0, len(s.SrcFuncs)+1)
	fns = append(fns, s.SrcFuncs...)
	var addWithAnons func(fn *ssa.Function)
	addWithAnons = func(fn *ssa.Function) {
		fns = append(fns, fn)
		for _, anon := range fn.AnonFuncs {
			addWithAnons(anon)
		}
	}
	if syn := s.Pkg.Func("init"); syn != nil {
		addWithAnons(syn)
	}
	return fns
}

// initFunction reports whether fn is an init function proper: the synthetic
// package initializer or a source-level init function (which SSA names
// "init#1", "init#2", ...).
func initFunction(fn *ssa.Function) bool {
	if fn.Signature.Recv() != nil {
		return false // a method named init is not an init function
	}
	if fn.Parent() != nil {
		return false // an anonymous function like "init#1$1" is not itself init
	}
	name := fn.Name()
	return name == "init" || strings.HasPrefix(name, "init#")
}

// initTimeFuncs returns the set of functions that can only run during package
// initialization. Such functions cannot execute after initialization, so
// their writes and escapes are as harmless as init's own. Members are:
//
//   - init functions themselves;
//   - unexported package-level functions whose every reference is a static
//     call (or defer) from a function already in the set;
//   - anonymous functions nested in a member, provided their closure value
//     does not escape to post-init reachability: stored into global-reachable
//     storage, returned, or started as a goroutine.
//
// The closure rule is deliberately lenient: a closure passed as a call
// argument stays init-time even though the callee could stash it — the same
// accepted gap as loaded values passed onward. The analysis is per-package,
// so an exported function may always be called from elsewhere, a method may
// be reached through an interface, and a named function used as a value may
// run at any time; none of those qualify.
func initTimeFuncs(fns []*ssa.Function) map[*ssa.Function]bool {
	// For each package function: the functions that statically call it, and
	// whether a reference disqualifies it — for a named function any use
	// other than as a static callee, for an anonymous function only an
	// escaping use.
	callers := make(map[*ssa.Function][]*ssa.Function)
	disqualified := make(map[*ssa.Function]bool)
	for _, fn := range fns {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				var calleeSlot *ssa.Value
				switch t := instr.(type) {
				case *ssa.Call:
					if !t.Call.IsInvoke() {
						calleeSlot = &t.Call.Value
					}
				case *ssa.Defer: // deferred calls in init still run during init
					if !t.Call.IsInvoke() {
						calleeSlot = &t.Call.Value
					}
				}
				for _, rand := range instr.Operands(nil) {
					ref := referencedFunc(*rand)
					if ref == nil {
						continue
					}
					switch {
					case rand == calleeSlot:
						callers[ref] = append(callers[ref], fn)
					case ref.Parent() != nil:
						if closureEscapes(instr, *rand) {
							disqualified[ref] = true
						}
					default:
						disqualified[ref] = true
					}
				}
			}
		}
	}

	// Optimistically admit every qualifying candidate, then remove any whose
	// caller (for an anonymous function, also its enclosing function) is
	// outside the set, until stable. The optimistic start is what lets
	// transitive and mutually recursive init helpers qualify.
	set := make(map[*ssa.Function]bool)
	var candidates []*ssa.Function
	for _, fn := range fns {
		if initFunction(fn) {
			set[fn] = true
			continue
		}
		if disqualified[fn] {
			continue
		}
		if fn.Parent() != nil {
			callers[fn] = append(callers[fn], fn.Parent())
		} else if fn.Signature.Recv() != nil || token.IsExported(fn.Name()) {
			continue
		}
		set[fn] = true
		candidates = append(candidates, fn)
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range candidates {
			if !set[fn] {
				continue
			}
			for _, caller := range callers[fn] {
				if !set[caller] {
					delete(set, fn)
					changed = true
					break
				}
			}
		}
	}
	return set
}

// referencedFunc returns the package function a value stands for: a function
// used directly, or through the closure created over it. Generic
// instantiations are attributed to their declaration.
func referencedFunc(v ssa.Value) *ssa.Function {
	switch t := v.(type) {
	case *ssa.Function:
		if o := t.Origin(); o != nil {
			return o
		}
		return t
	case *ssa.MakeClosure:
		return referencedFunc(t.Fn)
	}
	return nil
}

// closureEscapes reports whether this use of an init-time closure value lets
// it run after initialization: stored into global-reachable storage,
// returned (the caller may keep it), or started as a goroutine (which may
// outlive init). Uses that keep the value inside init-time execution —
// immediate calls, local variables, passing as a call argument — do not
// count; a value flowing onward through an intermediate (a phi, an interface
// conversion, a callee that stores its argument) is not chased.
func closureEscapes(instr ssa.Instruction, v ssa.Value) bool {
	switch t := instr.(type) {
	case *ssa.Store:
		return t.Val == v && storageRoot(t.Addr) != nil
	case *ssa.MapUpdate:
		return storageRoot(t.Map) != nil
	case *ssa.Return:
		return true
	case *ssa.Go:
		return true
	}
	return false
}

func checkFunction(pass *analysis.Pass, fn *ssa.Function, m *mutatorIndex) {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			checkInstruction(pass, instr, m)
		}
	}
}

func checkInstruction(pass *analysis.Pass, instr ssa.Instruction, m *mutatorIndex) {
	// 1. Writes. Chase the written address back through address projections
	// (&g.F, &g[i]) and loads of reference values (pointers, slices, maps
	// read out of a global) to a *ssa.Global root. Calls are checked against
	// the mutator index: passing a global-aliasing value into a callee
	// position the callee writes through is a mutation too.
	switch t := instr.(type) {
	case *ssa.Store:
		if g := m.storageRoot(t.Addr); g != nil {
			reportMutation(pass, instr.Pos(), g)
		}
	case *ssa.MapUpdate:
		if g := m.storageRoot(t.Map); g != nil {
			reportMutation(pass, instr.Pos(), g)
		}
	case *ssa.Send:
		if g := m.storageRoot(t.Chan); g != nil {
			reportMutation(pass, instr.Pos(), g)
		}
	case ssa.CallInstruction:
		checkCall(pass, t, m)
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
			// A synthetic instruction (e.g. the implicit interface conversion
			// of a call argument) has no position; report where its result is
			// used instead.
			if vi, ok := instr.(ssa.Value); ok {
				if refs := vi.Referrers(); refs != nil {
					for _, ref := range *refs {
						if p := ref.Pos(); p != token.NoPos {
							pos = p
							break
						}
					}
				}
			}
		}
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

// roots follows a value back to the storage it points into (or aliases),
// returning every terminal it can reach: through address projections, loads,
// map lookups, type assertions, aliasing conversions, tuple extractions,
// range iteration, phi nodes (all edges), and free variables (resolved to
// their closure bindings). A pointer, slice, or map read out of some root
// still refers to storage reachable from that root.
//
// When m is non-nil, results of same-package calls are resolved through the
// return-alias summaries: a callee known to return (part of) a global yields
// that global, and one returning a parameter continues the walk at the
// corresponding argument.
func roots(v ssa.Value, m *mutatorIndex) []ssa.Value {
	var out []ssa.Value
	var visited map[ssa.Value]bool
	var walk func(v ssa.Value)
	resolveCall := func(call *ssa.Call, idx int) bool {
		if m == nil {
			return false
		}
		c := call.Common()
		if c.IsInvoke() {
			return false
		}
		fn, ok := c.Value.(*ssa.Function)
		if !ok {
			return false
		}
		if o := fn.Origin(); o != nil {
			fn = o
		}
		ri := m.returns[fn][idx]
		if ri == nil {
			return false
		}
		for g := range ri.globals {
			out = append(out, g)
		}
		for i := range ri.params {
			if i < len(c.Args) {
				walk(c.Args[i])
			}
		}
		return true
	}
	walk = func(v ssa.Value) {
		for {
			switch t := v.(type) {
			case *ssa.FieldAddr:
				v = t.X
			case *ssa.IndexAddr:
				v = t.X
			case *ssa.Index:
				v = t.X
			case *ssa.Slice:
				v = t.X
			case *ssa.SliceToArrayPointer:
				v = t.X
			case *ssa.Lookup:
				v = t.X
			case *ssa.TypeAssert:
				v = t.X
			case *ssa.ChangeType:
				v = t.X
			case *ssa.Range:
				v = t.X
			case *ssa.Next:
				v = t.Iter
			case *ssa.UnOp:
				if t.Op != token.MUL {
					out = append(out, v)
					return
				}
				// A load of a local cell (an Alloc, possibly captured as a
				// free variable) yields whatever was stored into it: chase
				// the stored values. Loads of other addresses chase the
				// address chain itself.
				addr := t.X
				if fv, ok := addr.(*ssa.FreeVar); ok {
					if b := freeVarBinding(fv); b != nil {
						addr = b
					}
				}
				if alloc, ok := addr.(*ssa.Alloc); ok {
					if visited == nil {
						visited = make(map[ssa.Value]bool)
					}
					if visited[alloc] {
						return
					}
					visited[alloc] = true
					for _, ref := range *alloc.Referrers() {
						if st, ok := ref.(*ssa.Store); ok && st.Addr == alloc {
							walk(st.Val)
						}
					}
					return
				}
				v = t.X // load: chase the location the value was read from
			case *ssa.Extract:
				if call, ok := t.Tuple.(*ssa.Call); ok {
					if !resolveCall(call, t.Index) {
						out = append(out, v)
					}
					return
				}
				v = t.Tuple
			case *ssa.Call:
				if !resolveCall(t, 0) {
					out = append(out, v)
				}
				return
			case *ssa.FreeVar:
				b := freeVarBinding(t)
				if b == nil {
					out = append(out, v)
					return
				}
				v = b
			case *ssa.Phi:
				if visited == nil {
					visited = make(map[ssa.Value]bool)
				}
				if visited[t] {
					return
				}
				visited[t] = true
				for _, e := range t.Edges {
					walk(e)
				}
				return
			default:
				out = append(out, v)
				return
			}
		}
	}
	walk(v)
	return out
}

// freeVarBinding resolves a closure's free variable to the value bound at the
// closure's creation site in the enclosing function.
func freeVarBinding(fv *ssa.FreeVar) ssa.Value {
	fn := fv.Parent()
	idx := -1
	for i, v := range fn.FreeVars {
		if v == fv {
			idx = i
			break
		}
	}
	parent := fn.Parent()
	if idx < 0 || parent == nil {
		return nil
	}
	for _, block := range parent.Blocks {
		for _, instr := range block.Instrs {
			if mc, ok := instr.(*ssa.MakeClosure); ok && mc.Fn == fn && idx < len(mc.Bindings) {
				return mc.Bindings[idx]
			}
		}
	}
	return nil
}

// storageRoot returns the global whose storage v points into (or aliases), if
// any, so that a write through v is a write to global state.
func storageRoot(v ssa.Value) *ssa.Global {
	return firstGlobal(roots(v, nil))
}

func firstGlobal(vs []ssa.Value) *ssa.Global {
	for _, v := range vs {
		if g, ok := v.(*ssa.Global); ok {
			return g
		}
	}
	return nil
}

// addressRoot is the value chase restricted to pure address chains: it does
// not cross loads. It answers "is v the address of (part of) a global?",
// which is the question that matters for escape detection. Values *loaded
// from* globals are deliberately excluded — passing a loaded map or pointer
// to a function is unverifiable but pervasive (fmt.Println, errors.Is, value
// method calls), and flagging it would drown the signal. Phi nodes are
// followed through all edges: a conditional address is still an address.
func addressRoot(v ssa.Value) *ssa.Global {
	return addressRootVisited(v, nil)
}

func addressRootVisited(v ssa.Value, visited map[ssa.Value]bool) *ssa.Global {
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
		case *ssa.Phi:
			if visited == nil {
				visited = make(map[ssa.Value]bool)
			}
			if visited[t] {
				return nil
			}
			visited[t] = true
			for _, e := range t.Edges {
				if g := addressRootVisited(e, visited); g != nil {
					return g
				}
			}
			return nil
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
	case *ssa.Phi:
		return true // the phi's value is checked at each of its uses in turn
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
