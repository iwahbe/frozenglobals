package frozenglobals

import (
	"strings"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
)

func init() {
	register.Plugin("frozenglobals", newPlugin)
}

// Settings configures the linter under golangci-lint.
type Settings struct {
	// Mutators extends the known-mutators list: fully-qualified functions
	// (types.Func.FullName form, e.g. "encoding/json.Unmarshal" or
	// "(*encoding/json.Decoder).Decode"), each treated as writing through
	// every parameter.
	Mutators []string `json:"mutators"`
}

func newPlugin(settings any) (register.LinterPlugin, error) {
	s, err := register.DecodeSettings[Settings](settings)
	if err != nil {
		return nil, err
	}
	return plugin{settings: s}, nil
}

type plugin struct {
	settings Settings
}

var _ register.LinterPlugin = plugin{}

func (p plugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	if len(p.settings.Mutators) > 0 {
		if err := Analyzer.Flags.Set("mutators", strings.Join(p.settings.Mutators, ",")); err != nil {
			return nil, err
		}
	}
	return []*analysis.Analyzer{Analyzer}, nil
}

// GetLoadMode returns LoadModeTypesInfo because buildssa requires full type
// information, not just syntax.
func (plugin) GetLoadMode() string {
	return register.LoadModeTypesInfo
}
