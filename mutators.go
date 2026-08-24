package frozenglobals

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

// defaultMutators maps a callee — a builtin by name, or a function, method,
// or interface method by types.Func.FullName — to the signature positions it
// writes through. The list is a curated pass over the standard library:
// functions whose purpose is to mutate an argument, so a global-aliasing
// value passed there is a mutation even though the write itself (often via
// reflection) is invisible to the analysis.
var defaultMutators = map[string][]int{
	// builtins
	"append": {0}, // may write into the backing array when capacity allows
	"clear":  {0},
	"copy":   {0},
	"delete": {0},

	// encoding
	"encoding/json.Unmarshal":               {1},
	"(*encoding/json.Decoder).Decode":       {0},
	"encoding/json.Compact":                 {0},
	"encoding/json.Indent":                  {0},
	"encoding/json.HTMLEscape":              {0},
	"encoding/xml.Unmarshal":                {1},
	"(*encoding/xml.Decoder).Decode":        {0},
	"(*encoding/xml.Decoder).DecodeElement": {0},
	"(*encoding/gob.Decoder).Decode":        {0},
	"encoding/asn1.Unmarshal":               {1},
	"encoding/asn1.UnmarshalWithParams":     {1},
	"encoding/binary.Read":                  {2},
	"encoding/binary.Decode":                {2},

	// fmt scanning (the scanned-into operands are variadic)
	"fmt.Scan":    {0},
	"fmt.Scanln":  {0},
	"fmt.Scanf":   {1},
	"fmt.Sscan":   {1},
	"fmt.Sscanln": {1},
	"fmt.Sscanf":  {2},
	"fmt.Fscan":   {1},
	"fmt.Fscanln": {1},
	"fmt.Fscanf":  {2},

	// io
	"io.ReadFull":          {1},
	"io.ReadAtLeast":       {1},
	"(io.Reader).Read":     {0},
	"(io.ReaderAt).ReadAt": {0},

	// sort
	"sort.Sort":        {0},
	"sort.Stable":      {0},
	"sort.Ints":        {0},
	"sort.Strings":     {0},
	"sort.Float64s":    {0},
	"sort.Slice":       {0},
	"sort.SliceStable": {0},

	// slices (generic: instantiations are attributed to the declaration)
	"slices.Sort":           {0},
	"slices.SortFunc":       {0},
	"slices.SortStableFunc": {0},
	"slices.Reverse":        {0},
	"slices.Compact":        {0},
	"slices.CompactFunc":    {0},
	"slices.Delete":         {0},
	"slices.DeleteFunc":     {0},
	"slices.Insert":         {0},
	"slices.Replace":        {0},

	// maps
	"maps.Copy":       {0},
	"maps.DeleteFunc": {0},
	"maps.Insert":     {0},

	// container/heap
	"container/heap.Init":   {0},
	"container/heap.Push":   {0},
	"container/heap.Pop":    {0},
	"container/heap.Fix":    {0},
	"container/heap.Remove": {0},

	// rand
	"crypto/rand.Read": {0},
	"math/rand.Read":   {0},

	// database/sql (the scan destinations are variadic)
	"(*database/sql.Rows).Scan": {0},
	"(*database/sql.Row).Scan":  {0},
}

func init() {
	for _, t := range []string{"Int32", "Int64", "Uint32", "Uint64", "Uintptr", "Pointer"} {
		for _, op := range []string{"Add", "And", "Or", "Store", "Swap", "CompareAndSwap"} {
			if t == "Pointer" && (op == "Add" || op == "And" || op == "Or") {
				continue // these do not exist for unsafe.Pointer
			}
			defaultMutators["sync/atomic."+op+t] = []int{0}
		}
	}
}

// mutatorFact marks a function as writing through some of its parameters,
// declared with a //frozenglobals:mutator doc-comment directive. Exported as
// an analysis fact so importing packages see it.
type mutatorFact struct {
	All    bool  // every parameter may be mutated
	Params []int // otherwise: signature indices of mutated parameters
}

func (*mutatorFact) AFact() {}

func (f *mutatorFact) String() string {
	if f.All {
		return "mutator"
	}
	return fmt.Sprintf("mutator%v", f.Params)
}

// mutatorIndex answers, for a call site, which arguments the callee may write
// through. Same-package functions are summarized by analysis; callees the
// analysis cannot see through are covered by the known-mutators list
// (defaults plus the -mutators flag) and by facts from annotated packages.
type mutatorIndex struct {
	pass   *analysis.Pass
	byName map[string][]int // nil positions = every parameter
	// summaries holds mutated parameter indices for functions of this
	// package, indexed like fn.Params (a method's receiver is index 0).
	summaries map[*ssa.Function]map[int]bool
}

func newMutatorIndex(pass *analysis.Pass, extra []string) (*mutatorIndex, error) {
	m := &mutatorIndex{
		pass:      pass,
		byName:    defaultMutators,
		summaries: make(map[*ssa.Function]map[int]bool),
	}
	if len(extra) > 0 {
		m.byName = make(map[string][]int, len(defaultMutators)+len(extra))
		for name, idxs := range defaultMutators {
			m.byName[name] = idxs
		}
		for _, name := range extra {
			if name == "" || strings.ContainsAny(name, " \t") {
				return nil, fmt.Errorf("invalid -mutators entry %q", name)
			}
			m.byName[name] = nil
		}
	}
	return m, nil
}

// external returns the signature positions obj is known to write through,
// from an exported fact or the known-mutators list.
func (m *mutatorIndex) external(obj *types.Func) []int {
	sig := obj.Type().(*types.Signature)
	all := func() []int {
		idxs := make([]int, sig.Params().Len())
		for i := range idxs {
			idxs[i] = i
		}
		return idxs
	}
	var fact mutatorFact
	if m.pass.ImportObjectFact(obj, &fact) {
		if fact.All {
			return all()
		}
		return fact.Params
	}
	if idxs, ok := m.byName[obj.FullName()]; ok {
		if idxs == nil {
			return all()
		}
		return idxs
	}
	return nil
}

// mutatedValues returns the argument values of c that its callee may write
// through, with a packed variadic argument expanded to its elements, and the
// callee's name for reporting.
func (m *mutatorIndex) mutatedValues(c *ssa.CallCommon) ([]ssa.Value, string) {
	var (
		name   string
		args   = make(map[int]bool) // indices into c.Args
		offset int
		sig    *types.Signature
	)
	if c.IsInvoke() {
		name = c.Method.FullName()
		sig = c.Method.Type().(*types.Signature)
		for _, i := range m.external(c.Method) {
			args[i] = true
		}
	} else {
		switch t := c.Value.(type) {
		case *ssa.Builtin:
			name = t.Name()
			for _, i := range m.byName[name] {
				args[i] = true
			}
		case *ssa.Function:
			fn := t
			if o := fn.Origin(); o != nil {
				fn = o
			}
			name = fn.RelString(m.pass.Pkg)
			sig = fn.Signature
			if sig.Recv() != nil {
				offset = 1
			}
			for i := range c.Args {
				if m.summaries[fn][i] {
					args[i] = true
				}
			}
			if obj, ok := fn.Object().(*types.Func); ok {
				for _, i := range m.external(obj) {
					args[i+offset] = true
				}
			}
		default:
			return nil, ""
		}
	}
	var vals []ssa.Value
	for i := range c.Args {
		if !args[i] {
			continue
		}
		v := c.Args[i]
		if sig != nil && sig.Variadic() && i == len(c.Args)-1 {
			if elems, ok := packedVarargs(v); ok {
				vals = append(vals, elems...)
				continue
			}
		}
		vals = append(vals, v)
	}
	return vals, name
}

// packedVarargs unpacks the slice SSA builds for a non-spread call to a
// variadic function into the element values stored in it.
func packedVarargs(v ssa.Value) ([]ssa.Value, bool) {
	sl, ok := v.(*ssa.Slice)
	if !ok {
		return nil, false
	}
	alloc, ok := sl.X.(*ssa.Alloc)
	if !ok || alloc.Comment != "varargs" {
		return nil, false
	}
	var vals []ssa.Value
	for _, ref := range *alloc.Referrers() {
		ia, ok := ref.(*ssa.IndexAddr)
		if !ok || ia.X != alloc {
			continue
		}
		for _, use := range *ia.Referrers() {
			if st, ok := use.(*ssa.Store); ok && st.Addr == ia {
				vals = append(vals, st.Val)
			}
		}
	}
	return vals, true
}

// checkCall reports arguments that alias global-reachable storage passed into
// a callee position the callee is known to write through.
func checkCall(pass *analysis.Pass, call ssa.CallInstruction, m *mutatorIndex) {
	vals, name := m.mutatedValues(call.Common())
	for _, v := range vals {
		g := mutableRoot(v)
		if g == nil {
			continue
		}
		pass.Report(analysis.Diagnostic{
			Pos: call.Pos(),
			Message: fmt.Sprintf(
				"%s is mutated (via %s) outside of package initialization",
				relName(pass, g), name),
		})
	}
}

// mutableRoot returns the global whose storage the argument value aliases, if
// writing through the value can reach it. Pure address chains are excluded:
// those are already reported by the escape check.
func mutableRoot(v ssa.Value) *ssa.Global {
	v = unwrapInterface(v)
	if addressRoot(v) != nil {
		return nil
	}
	switch v.Type().Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Slice:
		return storageRoot(v)
	}
	return nil
}

func unwrapInterface(v ssa.Value) ssa.Value {
	for {
		switch t := v.(type) {
		case *ssa.MakeInterface:
			v = t.X
		case *ssa.ChangeInterface:
			v = t.X
		default:
			return v
		}
	}
}

// paramRoot returns the reference-carrying parameter of fn whose storage v
// reaches, if any.
func paramRoot(fn *ssa.Function, v ssa.Value) *ssa.Parameter {
	p, ok := chase(unwrapInterface(v)).(*ssa.Parameter)
	if !ok || p.Parent() != fn {
		return nil
	}
	switch p.Type().Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Slice, *types.Interface:
		return p
	}
	return nil
}

// paramMutators computes, for every function in the package, the set of
// parameters it provably writes through — directly, or by passing the
// parameter into a mutated position of another callee. Computed as a least
// fixpoint: only proven mutation is recorded, so an unknown callee never
// taints a parameter.
func paramMutators(m *mutatorIndex, fns []*ssa.Function) {
	record := func(fn *ssa.Function, v ssa.Value) bool {
		p := paramRoot(fn, v)
		if p == nil {
			return false
		}
		for i, q := range fn.Params {
			if q == p {
				return setSummary(m, fn, i)
			}
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range fns {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					switch t := instr.(type) {
					case *ssa.Store:
						if record(fn, t.Addr) {
							changed = true
						}
					case *ssa.MapUpdate:
						if record(fn, t.Map) {
							changed = true
						}
					case ssa.CallInstruction:
						vals, _ := m.mutatedValues(t.Common())
						for _, v := range vals {
							if record(fn, v) {
								changed = true
							}
						}
					}
				}
			}
		}
	}
}

// setSummary records that fn may write through fn.Params[i], reporting
// whether that was new information.
func setSummary(m *mutatorIndex, fn *ssa.Function, i int) bool {
	if m.summaries[fn][i] {
		return false
	}
	if m.summaries[fn] == nil {
		m.summaries[fn] = make(map[int]bool)
	}
	m.summaries[fn][i] = true
	return true
}

// collectDirectives parses //frozenglobals:mutator doc-comment directives,
// exports them as facts for importing packages, and seeds the local
// summaries. The bare form marks every parameter; the argument form
// (`//frozenglobals:mutator x y`) marks the named parameters only.
func collectDirectives(pass *analysis.Pass, prog *ssa.Program, m *mutatorIndex) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Doc == nil {
				continue
			}
			for _, com := range fd.Doc.List {
				rest, ok := strings.CutPrefix(com.Text, "//frozenglobals:mutator")
				if !ok || (rest != "" && !strings.HasPrefix(rest, " ")) {
					continue
				}
				obj, ok := pass.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				sig := obj.Type().(*types.Signature)
				names := strings.Fields(rest)
				fact := &mutatorFact{All: len(names) == 0}
				valid := true
				for _, n := range names {
					idx := -1
					for i := 0; i < sig.Params().Len(); i++ {
						if sig.Params().At(i).Name() == n {
							idx = i
							break
						}
					}
					if idx < 0 {
						pass.Reportf(fd.Name.Pos(),
							"invalid //frozenglobals:mutator directive: no parameter named %q", n)
						valid = false
						break
					}
					fact.Params = append(fact.Params, idx)
				}
				if !valid {
					continue
				}
				pass.ExportObjectFact(obj, fact)
				fn := prog.FuncValue(obj)
				if fn == nil {
					continue
				}
				offset := 0
				if sig.Recv() != nil {
					offset = 1
				}
				idxs := fact.Params
				if fact.All {
					idxs = idxs[:0]
					for i := 0; i < sig.Params().Len(); i++ {
						idxs = append(idxs, i)
					}
				}
				for _, i := range idxs {
					setSummary(m, fn, i+offset)
				}
			}
		}
	}
}
