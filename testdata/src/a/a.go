package a

import "regexp"

type Policy struct {
	Retries int
	Name    string
}

// --- Globals that are used like constants: all allowed. ---

var version string // set via -ldflags at link time

var DefaultPolicy = Policy{Retries: 3, Name: "default"}

var matcher = regexp.MustCompile(`^a+$`)

var lookup = map[string]int{"a": 1}

var seq = []int{1, 2, 3}

var arr = [4]int{}

var ptr = &Policy{Retries: 1}

var counter int

var initialized bool

// --- Init-time mutation: all allowed. ---

func init() {
	counter = 1
	lookup["b"] = 2
	seq[0] = 9
	arr[1] = 9
	ptr.Retries = 2
	DefaultPolicy.Name = "renamed"
	registerPolicy(&DefaultPolicy) // escape during init is fine
	initialized = true

	// Anonymous function nested in init counts as init time.
	func() {
		counter = 2
	}()
}

func init() { // second init: SSA names this init#2
	counter = 3
}

func registerPolicy(*Policy) {}

func registerInt(*int) {}

// --- Reads outside init: all allowed. ---

func Reads() (int, bool) {
	n := counter
	p := DefaultPolicy       // value copy
	p.Retries = 10           // mutating the copy is fine
	_ = matcher.MatchString  // value read
	v := lookup["a"]         // map read
	w := seq[1]              // slice read
	x := ptr.Retries         // read through pointer
	return n + v + w + x + p.Retries, initialized
}

// --- Post-init mutation: all reported. ---

func Mutations() {
	counter = 4                // want `counter is mutated outside of package initialization`
	counter++                  // want `counter is mutated outside of package initialization`
	initialized = false        // want `initialized is mutated outside of package initialization`
	DefaultPolicy.Retries = 10 // want `DefaultPolicy is mutated outside of package initialization`
	lookup["c"] = 3            // want `lookup is mutated outside of package initialization`
	seq[2] = 7                 // want `seq is mutated outside of package initialization`
	seq[1:][0] = 7             // want `seq is mutated outside of package initialization`
	arr[0] = 7                 // want `arr is mutated outside of package initialization`
	ptr.Retries = 7            // want `ptr is mutated outside of package initialization`
}

func MutateThroughLocalAlias() {
	p := &counter
	*p = 5 // want `counter is mutated outside of package initialization`
}

// --- Post-init escapes: all reported. ---

func Escapes() {
	registerPolicy(&DefaultPolicy) // want `address of DefaultPolicy escapes`
	registerInt(&counter)          // want `address of counter escapes`
	registerInt(&arr[0])           // want `address of arr escapes`
	// Assigning to sink is itself a mutation, and &counter escapes into it.
	sink = &counter // want `sink is mutated outside of package initialization` `address of counter escapes`
}

var sink *int

func ReturnEscape() *Policy {
	return &DefaultPolicy // want `address of DefaultPolicy escapes`
}
