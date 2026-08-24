package frozenglobals_test

import (
	"testing"

	"github.com/iwahbe/frozenglobals"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), frozenglobals.Analyzer, "a", "b")
}
