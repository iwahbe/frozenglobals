package flagged

// opaque stands in for a function whose mutation the analysis cannot see and
// whose source cannot be annotated; the test adds it to the known-mutators
// list via the -mutators flag.
var state = map[string]int{}

func opaque(m map[string]int) {}

func Mutate() {
	opaque(state) // want `state is mutated \(via opaque\) outside of package initialization`
}
