package b

import "a"

// Mutating another package's global is also reported (the io.EOF = nil class
// of bug), qualified with the package name.
func Mutate() {
	a.DefaultPolicy.Retries = 1 // want `a.DefaultPolicy is mutated outside of package initialization`
}

func Escape() *a.Policy {
	return &a.DefaultPolicy // want `address of a.DefaultPolicy escapes`
}
