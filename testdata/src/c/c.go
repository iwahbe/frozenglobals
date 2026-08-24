package c

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
)

type Config struct {
	Timeout int
}

var cfg = &Config{}
var limits = map[string]int{}
var buf = []byte{1, 2, 3}
var defaults = Config{Timeout: 1}
var words = []string{"b", "a"}
var num = new(int)
var reader io.Reader

// --- Same-package helpers that provably mutate a parameter. ---

func setTimeout(c *Config, n int) { c.Timeout = n }

func addLimit(m map[string]int, k string) { m[k] = 1 }

func fillFirst(b []byte) { b[0] = 1 }

func indirect(c *Config) { setTimeout(c, 2) } // transitively mutating

func readOnly(c *Config) int { return c.Timeout }

func byValue(c Config) int { c.Timeout = 3; return c.Timeout } // mutates its copy

func init() {
	setTimeout(cfg, 1) // init-time mutation through a helper: allowed
}

func Mutations() {
	setTimeout(cfg, 5)    // want `cfg is mutated \(via setTimeout\) outside of package initialization`
	addLimit(limits, "x") // want `limits is mutated \(via addLimit\) outside of package initialization`
	fillFirst(buf)        // want `buf is mutated \(via fillFirst\) outside of package initialization`
	indirect(cfg)         // want `cfg is mutated \(via indirect\) outside of package initialization`
	fillFirst(buf[1:])    // want `buf is mutated \(via fillFirst\) outside of package initialization`
}

func Reads() int {
	_ = readOnly(cfg) // read-only parameter: fine
	local := &Config{}
	setTimeout(local, 1) // mutating a local through a helper: fine
	return byValue(defaults)
}

// A helper whose mutation flows through a known external mutator.
func viaUnmarshal(c *Config, data []byte) {
	json.Unmarshal(data, c)
}

func UnmarshalHelper(data []byte) {
	viaUnmarshal(cfg, data) // want `cfg is mutated \(via viaUnmarshal\) outside of package initialization`
}

// --- Known mutators from the standard library. ---

func Stdlib(data []byte) {
	json.Unmarshal(data, cfg) // want `cfg is mutated \(via encoding/json.Unmarshal\) outside of package initialization`
	sort.Strings(words)       // want `words is mutated \(via sort.Strings\) outside of package initialization`
	fmt.Sscan("1", num)       // want `num is mutated \(via fmt.Sscan\) outside of package initialization`
	reader.Read(buf)          // want `buf is mutated \(via \(io.Reader\).Read\) outside of package initialization`

	json.Unmarshal(data, &defaults) // want `address of defaults escapes`

	var local Config
	json.Unmarshal(data, &local) // unmarshal into a local: fine
	fmt.Sscan("1", &local.Timeout)
}

func Builtins() {
	delete(limits, "x")    // want `limits is mutated \(via delete\) outside of package initialization`
	clear(buf)             // want `buf is mutated \(via clear\) outside of package initialization`
	copy(buf, []byte("x")) // want `buf is mutated \(via copy\) outside of package initialization`
	_ = append(buf, 4)     // want `buf is mutated \(via append\) outside of package initialization`

	local := make([]byte, 3)
	copy(local, buf)          // global as copy source: fine
	_ = append(local, buf...) // global as append source: fine
}

// --- Directive-annotated mutators. ---

// ReflectSet copies src into dst by reflection; the analysis cannot see the
// writes, so the directive declares them.
//
//frozenglobals:mutator dst
func ReflectSet(dst, src any) {} // want ReflectSet:`mutator\[0\]`

// Reset mutates every reference-carrying parameter.
//
//frozenglobals:mutator
func Reset(m map[string]int, n int) {} // want Reset:`mutator`

func Directives() {
	ReflectSet(cfg, nil) // want `cfg is mutated \(via ReflectSet\) outside of package initialization`
	ReflectSet(nil, cfg) // src is not marked: fine
	Reset(limits, 1)     // want `limits is mutated \(via Reset\) outside of package initialization`
}

//frozenglobals:mutator nosuch
func BadDirective(x int) {} // want `//frozenglobals:mutator directive: no parameter named "nosuch"`

// --- Return values that alias global storage. ---

func getCfg() *Config { return cfg }

func passthrough(c *Config) *Config { return c }

func getIndirect() *Config { return passthrough(cfg) }

func getPair() (*Config, error) { return cfg, nil }

func freshCfg() *Config { c := *cfg; return &c } // returns a copy: fine

func ReturnAliases() {
	getCfg().Timeout = 1 // want `cfg is mutated outside of package initialization`
	p := getCfg()
	p.Timeout = 2                // want `cfg is mutated outside of package initialization`
	passthrough(cfg).Timeout = 3 // want `cfg is mutated outside of package initialization`
	getIndirect().Timeout = 4    // want `cfg is mutated outside of package initialization`
	q, _ := getPair()
	q.Timeout = 5           // want `cfg is mutated outside of package initialization`
	setTimeout(getCfg(), 6) // want `cfg is mutated \(via setTimeout\) outside of package initialization`

	freshCfg().Timeout = 7 // a copy: fine
	local := &Config{}
	passthrough(local).Timeout = 8 // fine
}

// --- Known mutators that write through their receiver. ---

var registry = &sync.Map{}
var logbuf = &bytes.Buffer{}

func ReceiverMutators() {
	registry.Store("k", 1)  // want `registry is mutated \(via \(\*sync.Map\).Store\) outside of package initialization`
	logbuf.WriteString("x") // want `logbuf is mutated \(via \(\*bytes.Buffer\).WriteString\) outside of package initialization`

	_, _ = registry.Load("k") // read-only method: fine
	var local sync.Map
	local.Store("k", 1) // local receiver: fine
}

// Same-package methods are summarized like any function; the receiver is a
// parameter.
type Box struct{ n int }

func (b *Box) Set(n int) { b.n = n }

var box = &Box{}

func SetBox() {
	box.Set(3) // want `box is mutated \(via \(\*(c\.)?Box\)\.Set\) outside of package initialization`
}

// A directive can name the receiver.
//
//frozenglobals:mutator b
func (b *Box) Merge(other *Box) {} // want Merge:`mutator\[-1\]`

func MergeBox() {
	box.Merge(nil) // want `box is mutated \(via \(\*(c\.)?Box\)\.Merge\) outside of package initialization`
}

// --- Reassigning append reports once, via the store. ---

func AppendReassign() {
	buf = append(buf, 5) // want `buf is mutated outside of package initialization`
}
