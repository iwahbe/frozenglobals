package d

import "c"

// Directive facts flow across packages: c.ReflectSet declares (via
// //frozenglobals:mutator dst) that it writes through dst.
var conf = &c.Config{}

func Mutate() {
	c.ReflectSet(conf, nil) // want `conf is mutated \(via c.ReflectSet\) outside of package initialization`
	c.ReflectSet(nil, conf) // src is not marked: fine
}
