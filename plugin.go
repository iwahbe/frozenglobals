package frozenglobals

import (
	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
)

func init() {
	register.Plugin("frozenglobals", newPlugin)
}

func newPlugin(_ any) (register.LinterPlugin, error) {
	return plugin{}, nil
}

type plugin struct{}

var _ register.LinterPlugin = plugin{}

func (plugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{Analyzer}, nil
}

// GetLoadMode returns LoadModeTypesInfo because buildssa requires full type
// information, not just syntax.
func (plugin) GetLoadMode() string {
	return register.LoadModeTypesInfo
}
