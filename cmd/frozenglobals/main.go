// Command frozenglobals runs the analyzer standalone:
//
//	frozenglobals ./...
package main

import (
	"github.com/iwahbe/frozenglobals"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(frozenglobals.Analyzer)
}
