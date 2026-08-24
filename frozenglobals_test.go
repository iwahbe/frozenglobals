package frozenglobals_test

import (
	"testing"

	"github.com/iwahbe/frozenglobals"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), frozenglobals.Analyzer, "a", "b", "c", "d")
}

func TestMutatorsFlag(t *testing.T) {
	if err := frozenglobals.Analyzer.Flags.Set("mutators", "flagged.opaque"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := frozenglobals.Analyzer.Flags.Set("mutators", ""); err != nil {
			t.Fatal(err)
		}
	}()
	analysistest.Run(t, analysistest.TestData(), frozenglobals.Analyzer, "flagged")
}
