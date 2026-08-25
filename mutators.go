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
// writes through; position -1 is the receiver. The list is a curated pass
// over the standard library: functions whose purpose is to mutate an
// argument or their receiver's state, so a global-aliasing value passed
// there is a mutation even though the write itself (often via reflection) is
// invisible to the analysis. I/O receivers (io.Writer implementations,
// *os.File, *log.Logger) are deliberately absent: writing to a global
// destination is not global-state mutation in the sense this linter polices.
var defaultMutators = map[string][]int{
	// builtins
	"append": {0}, // may write into the backing array when capacity allows
	"clear":  {0},
	"close":  {0},
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

	// sync: state mutated through the receiver
	"(*sync.Mutex).Lock":           {-1},
	"(*sync.Mutex).TryLock":        {-1},
	"(*sync.Mutex).Unlock":         {-1},
	"(*sync.RWMutex).Lock":         {-1},
	"(*sync.RWMutex).TryLock":      {-1},
	"(*sync.RWMutex).Unlock":       {-1},
	"(*sync.RWMutex).RLock":        {-1},
	"(*sync.RWMutex).TryRLock":     {-1},
	"(*sync.RWMutex).RUnlock":      {-1},
	"(*sync.Once).Do":              {-1},
	"(*sync.WaitGroup).Add":        {-1},
	"(*sync.WaitGroup).Done":       {-1},
	"(*sync.Pool).Get":             {-1},
	"(*sync.Pool).Put":             {-1},
	"(*sync.Map).Store":            {-1},
	"(*sync.Map).Delete":           {-1},
	"(*sync.Map).Clear":            {-1},
	"(*sync.Map).LoadOrStore":      {-1},
	"(*sync.Map).LoadAndDelete":    {-1},
	"(*sync.Map).Swap":             {-1},
	"(*sync.Map).CompareAndSwap":   {-1},
	"(*sync.Map).CompareAndDelete": {-1},

	// bytes.Buffer / strings.Builder / in-memory readers
	"(*bytes.Buffer).Write":          {-1},
	"(*bytes.Buffer).WriteString":    {-1},
	"(*bytes.Buffer).WriteByte":      {-1},
	"(*bytes.Buffer).WriteRune":      {-1},
	"(*bytes.Buffer).WriteTo":        {-1},
	"(*bytes.Buffer).Read":           {-1, 0},
	"(*bytes.Buffer).ReadByte":       {-1},
	"(*bytes.Buffer).ReadRune":       {-1},
	"(*bytes.Buffer).ReadString":     {-1},
	"(*bytes.Buffer).ReadBytes":      {-1},
	"(*bytes.Buffer).ReadFrom":       {-1},
	"(*bytes.Buffer).Next":           {-1},
	"(*bytes.Buffer).Reset":          {-1},
	"(*bytes.Buffer).Truncate":       {-1},
	"(*bytes.Buffer).Grow":           {-1},
	"(*strings.Builder).Write":       {-1},
	"(*strings.Builder).WriteString": {-1},
	"(*strings.Builder).WriteByte":   {-1},
	"(*strings.Builder).WriteRune":   {-1},
	"(*strings.Builder).Reset":       {-1},
	"(*strings.Builder).Grow":        {-1},
	"(*bytes.Reader).Read":           {-1, 0},
	"(*bytes.Reader).Seek":           {-1},
	"(*bytes.Reader).Reset":          {-1},
	"(*strings.Reader).Read":         {-1, 0},
	"(*strings.Reader).Seek":         {-1},
	"(*strings.Reader).Reset":        {-1},

	// container/list
	"(*container/list.List).PushBack":      {-1},
	"(*container/list.List).PushFront":     {-1},
	"(*container/list.List).PushBackList":  {-1},
	"(*container/list.List).PushFrontList": {-1},
	"(*container/list.List).InsertBefore":  {-1},
	"(*container/list.List).InsertAfter":   {-1},
	"(*container/list.List).Remove":        {-1},
	"(*container/list.List).Init":          {-1},
	"(*container/list.List).MoveToFront":   {-1},
	"(*container/list.List).MoveToBack":    {-1},
	"(*container/list.List).MoveBefore":    {-1},
	"(*container/list.List).MoveAfter":     {-1},

	// time
	"(*time.Timer).Reset":  {-1},
	"(*time.Timer).Stop":   {-1},
	"(*time.Ticker).Reset": {-1},
	"(*time.Ticker).Stop":  {-1},

	// math/rand
	"(*math/rand.Rand).Seed":    {-1},
	"(*math/rand.Rand).Shuffle": {-1},
	"(*math/rand.Rand).Read":    {-1, 0},

	// regexp
	"(*regexp.Regexp).Longest": {-1},
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
	// The atomic wrapper types mutate through their receiver. (The generic
	// atomic.Pointer[T] is absent: method names of generic types embed the
	// type parameter and are not matched.)
	for _, t := range []string{"Bool", "Int32", "Int64", "Uint32", "Uint64", "Uintptr", "Value"} {
		base := "(*sync/atomic." + t + ")."
		defaultMutators[base+"Store"] = []int{-1}
		defaultMutators[base+"Swap"] = []int{-1}
		defaultMutators[base+"CompareAndSwap"] = []int{-1}
		switch t {
		case "Bool", "Value":
		default:
			defaultMutators[base+"Add"] = []int{-1}
			defaultMutators[base+"And"] = []int{-1}
			defaultMutators[base+"Or"] = []int{-1}
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
// through, and which globals or parameters a callee's results alias.
// Same-package functions are summarized by analysis; callees the analysis
// cannot see through are covered by the known-mutators list (defaults plus
// the -mutators flag) and by facts from annotated packages.
type mutatorIndex struct {
	pass   *analysis.Pass
	byName map[string][]int // nil positions = receiver and every parameter
	// summaries holds mutated parameter indices for functions of this
	// package, indexed like fn.Params (a method's receiver is index 0).
	summaries map[*ssa.Function]map[int]bool
	// deep marks the subset of summaries whose write goes through values
	// loaded out of the parameter's storage rather than (only) to that
	// storage itself. Only a deep write can affect the elements of a packed
	// variadic call, whose backing array is call-site fresh.
	deep map[*ssa.Function]map[int]bool
	// returns holds, per function and result index, the globals and
	// parameters (fn.Params indices) the result may alias.
	returns map[*ssa.Function]map[int]*retInfo
}

// retInfo records what one result of a function may alias.
type retInfo struct {
	globals map[*ssa.Global]bool
	params  map[int]bool
}

func newMutatorIndex(pass *analysis.Pass, extra []string) (*mutatorIndex, error) {
	m := &mutatorIndex{
		pass:      pass,
		byName:    defaultMutators,
		summaries: make(map[*ssa.Function]map[int]bool),
		deep:      make(map[*ssa.Function]map[int]bool),
		returns:   make(map[*ssa.Function]map[int]*retInfo),
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

// external returns the signature positions obj is known to write through
// (-1 is the receiver), from an exported fact or the known-mutators list.
func (m *mutatorIndex) external(obj *types.Func) []int {
	sig := obj.Type().(*types.Signature)
	all := func() []int {
		var idxs []int
		if sig.Recv() != nil {
			idxs = append(idxs, -1)
		}
		for i := 0; i < sig.Params().Len(); i++ {
			idxs = append(idxs, i)
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

// mutatedValue is one argument value a callee may write through. deep means
// the callee writes through values loaded out of val's storage, not (only)
// to that storage itself.
type mutatedValue struct {
	val  ssa.Value
	deep bool
}

// mutatedValues returns the argument values of c that its callee may write
// through, and the callee's name for reporting. A packed variadic argument is
// expanded to its elements only for a deep write: a write to the slice's own
// storage cannot affect them, since a non-spread call allocates the backing
// array fresh. Curated external mutators of a variadic position (fmt.Scan et
// al.) mutate through the packed values, so those positions are deep.
func (m *mutatorIndex) mutatedValues(c *ssa.CallCommon) ([]mutatedValue, string) {
	var (
		name   string
		args   = make(map[int]bool) // indices into c.Args
		deep   = make(map[int]bool)
		recv   ssa.Value // invoke-mode receiver, when marked
		offset int
		sig    *types.Signature
	)
	if c.IsInvoke() {
		name = c.Method.FullName()
		sig = c.Method.Type().(*types.Signature)
		for _, i := range m.external(c.Method) {
			if i == -1 {
				recv = c.Value
			} else {
				args[i] = true
				if variadicParam(sig, i) {
					deep[i] = true
				}
			}
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
				offset = 1 // c.Args[0] is the receiver
			}
			for i := range c.Args {
				if m.summaries[fn][i] {
					args[i] = true
				}
				if m.deep[fn][i] {
					deep[i] = true
				}
			}
			if obj, ok := fn.Object().(*types.Func); ok {
				for _, i := range m.external(obj) {
					if j := i + offset; j >= 0 && j < len(c.Args) {
						args[j] = true
						if variadicParam(sig, i) {
							deep[j] = true
						}
					}
				}
			}
		default:
			return nil, ""
		}
	}
	var vals []mutatedValue
	for i := range c.Args {
		if !args[i] {
			continue
		}
		v := c.Args[i]
		if deep[i] && sig != nil && sig.Variadic() && i == len(c.Args)-1 {
			if elems, ok := packedVarargs(v); ok {
				for _, e := range elems {
					vals = append(vals, mutatedValue{val: e})
				}
				continue
			}
		}
		vals = append(vals, mutatedValue{val: v, deep: deep[i]})
	}
	if recv != nil {
		vals = append(vals, mutatedValue{val: recv})
	}
	return vals, name
}

// variadicParam reports whether signature parameter i is the variadic slice.
func variadicParam(sig *types.Signature, i int) bool {
	return sig.Variadic() && i == sig.Params().Len()-1
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
// a callee position the callee is known to write through. A call whose
// result is assigned back over the same global (`g = append(g, x)`) is not
// reported here: the assignment's own mutation report already covers it.
func checkCall(pass *analysis.Pass, call ssa.CallInstruction, m *mutatorIndex) {
	vals, name := m.mutatedValues(call.Common())
	if len(vals) == 0 {
		return
	}
	var storedInto map[*ssa.Global]bool
	if v, ok := call.(ssa.Value); ok {
		if refs := v.Referrers(); refs != nil {
			for _, ref := range *refs {
				if st, ok := ref.(*ssa.Store); ok && st.Val == v {
					if g := m.storageRoot(st.Addr); g != nil {
						if storedInto == nil {
							storedInto = make(map[*ssa.Global]bool)
						}
						storedInto[g] = true
					}
				}
			}
		}
	}
	for _, mv := range vals {
		g := m.mutableRoot(mv.val)
		if g == nil || storedInto[g] {
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

// storageRoot is the summary-aware chase: it additionally resolves results of
// same-package calls known to return global or parameter aliases.
func (m *mutatorIndex) storageRoot(v ssa.Value) *ssa.Global {
	return firstGlobal(roots(v, m))
}

// mutableRoot returns the global whose storage the argument value aliases, if
// writing through the value can reach it. Pure address chains are excluded:
// those are already reported by the escape check.
func (m *mutatorIndex) mutableRoot(v ssa.Value) *ssa.Global {
	v = unwrapInterface(v)
	if addressRoot(v) != nil {
		return nil
	}
	switch v.Type().Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.Interface:
		return m.storageRoot(v)
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
func (m *mutatorIndex) paramRoot(fn *ssa.Function, v ssa.Value) *ssa.Parameter {
	for _, r := range roots(unwrapInterface(v), m) {
		p, ok := r.(*ssa.Parameter)
		if !ok || p.Parent() != fn {
			continue
		}
		switch p.Type().Underlying().(type) {
		case *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.Interface:
			return p
		}
	}
	return nil
}

func paramIndexOf(fn *ssa.Function, p *ssa.Parameter) int {
	for i, q := range fn.Params {
		if q == p {
			return i
		}
	}
	return -1
}

// pureParam returns the parameter of fn that v is a pure projection of —
// address projections, reslicings, and value-preserving conversions, never
// crossing a load. A write that reaches a parameter only through such a chain
// touches the parameter's own storage; one that crosses a load goes through
// the values held in it.
func pureParam(fn *ssa.Function, v ssa.Value) *ssa.Parameter {
	for {
		switch t := v.(type) {
		case *ssa.Parameter:
			if t.Parent() == fn {
				return t
			}
			return nil
		case *ssa.FieldAddr:
			v = t.X
		case *ssa.IndexAddr:
			v = t.X
		case *ssa.Slice:
			v = t.X
		case *ssa.SliceToArrayPointer:
			v = t.X
		case *ssa.ChangeType:
			v = t.X
		case *ssa.MakeInterface:
			v = t.X
		case *ssa.ChangeInterface:
			v = t.X
		case *ssa.TypeAssert:
			v = t.X
		default:
			return nil
		}
	}
}

// paramMutators computes two summaries for every function in the package,
// as one least fixpoint:
//
//   - the parameters it provably writes through — directly, or by passing
//     the parameter into a mutated position of another callee;
//   - the globals and parameters each of its results may alias.
//
// Only proven facts are recorded, so an unknown callee never taints a
// parameter and reads stay unreported.
func paramMutators(m *mutatorIndex, fns []*ssa.Function) {
	// deep: the write reaches the parameter through a load (or the callee's
	// own write is deep), so it goes through the values the parameter's
	// storage holds, not (only) that storage itself.
	record := func(fn *ssa.Function, v ssa.Value, deep bool) bool {
		p := m.paramRoot(fn, v)
		if p == nil {
			return false
		}
		i := paramIndexOf(fn, p)
		if i < 0 {
			return false
		}
		changed := setIndex(m.summaries, fn, i)
		if deep || pureParam(fn, v) != p {
			changed = setIndex(m.deep, fn, i) || changed
		}
		return changed
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range fns {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					switch t := instr.(type) {
					case *ssa.Store:
						if record(fn, t.Addr, false) {
							changed = true
						}
					case *ssa.MapUpdate:
						if record(fn, t.Map, false) {
							changed = true
						}
					case *ssa.Send:
						if record(fn, t.Chan, false) {
							changed = true
						}
					case *ssa.Return:
						for j, res := range t.Results {
							for _, r := range roots(res, m) {
								switch r := r.(type) {
								case *ssa.Global:
									if m.setReturnGlobal(fn, j, r) {
										changed = true
									}
								case *ssa.Parameter:
									if i := paramIndexOf(fn, r); i >= 0 && m.setReturnParam(fn, j, i) {
										changed = true
									}
								}
							}
						}
					case ssa.CallInstruction:
						vals, _ := m.mutatedValues(t.Common())
						for _, mv := range vals {
							if record(fn, mv.val, mv.deep) {
								changed = true
							}
						}
					}
				}
			}
		}
	}
}

func (m *mutatorIndex) retInfoFor(fn *ssa.Function, result int) *retInfo {
	if m.returns[fn] == nil {
		m.returns[fn] = make(map[int]*retInfo)
	}
	ri := m.returns[fn][result]
	if ri == nil {
		ri = &retInfo{globals: make(map[*ssa.Global]bool), params: make(map[int]bool)}
		m.returns[fn][result] = ri
	}
	return ri
}

func (m *mutatorIndex) setReturnGlobal(fn *ssa.Function, result int, g *ssa.Global) bool {
	ri := m.retInfoFor(fn, result)
	if ri.globals[g] {
		return false
	}
	ri.globals[g] = true
	return true
}

func (m *mutatorIndex) setReturnParam(fn *ssa.Function, result, param int) bool {
	ri := m.retInfoFor(fn, result)
	if ri.params[param] {
		return false
	}
	ri.params[param] = true
	return true
}

// setIndex records index i for fn in a summary map, reporting whether that
// was new information.
func setIndex(mm map[*ssa.Function]map[int]bool, fn *ssa.Function, i int) bool {
	if mm[fn][i] {
		return false
	}
	if mm[fn] == nil {
		mm[fn] = make(map[int]bool)
	}
	mm[fn][i] = true
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
					idx := -2
					if r := sig.Recv(); r != nil && r.Name() == n {
						idx = -1 // the receiver
					}
					for i := 0; idx == -2 && i < sig.Params().Len(); i++ {
						if sig.Params().At(i).Name() == n {
							idx = i
						}
					}
					if idx == -2 {
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
					if sig.Recv() != nil {
						idxs = append(idxs, -1)
					}
					for i := 0; i < sig.Params().Len(); i++ {
						idxs = append(idxs, i)
					}
				}
				for _, i := range idxs {
					if j := i + offset; j >= 0 {
						setIndex(m.summaries, fn, j)
						if i >= 0 && variadicParam(sig, i) {
							setIndex(m.deep, fn, j)
						}
					}
				}
			}
		}
	}
}
