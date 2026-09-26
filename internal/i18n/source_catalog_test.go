package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Check real presentation call sites, not an independent list of expected
// strings. A new prompt or changed format must ship with matching Chinese copy.
func TestTerminalSourcesHaveCopyAndMatchingArguments(t *testing.T) {
	directive := regexp.MustCompile(`%(?:\[[0-9]+\])?[+#0 .\-0-9]*[a-zA-Z%]`)
	letters := regexp.MustCompile(`[a-zA-Z]`)
	fset := token.NewFileSet()
	for _, dir := range []string{"../cli", "../launch", "../provenance", "../effects", "../sensor", "../daemon", "../store", "../telemetry", "../../cmd/agentprov-sensor"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				index := -1
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					switch fn.Name {
					case "commandText":
						index = 1
					case "commandErrorf", "messagef":
						index = 0
					}
				case *ast.SelectorExpr:
					if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "i18n" {
						switch fn.Sel.Name {
						case "T":
							index = 1
						case "Errorf":
							index = 0
						}
					}
				}
				if index < 0 || index >= len(call.Args) {
					return true
				}
				literal, ok := call.Args[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				source, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if !letters.MatchString(directive.ReplaceAllString(source, "")) {
					return true
				}
				if !HasChinese(source) {
					t.Errorf("%s missing Chinese: %q", fset.Position(literal.Pos()), source)
					return true
				}
				// Native capability/spool diagnostics lose their typed wrappers
				// when saved. New formats need both live and historical display.
				if fn, ok := call.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "Errorf" &&
					(dir == "../sensor" || dir == "../store" || dir == "../daemon" || (dir == "../telemetry" && strings.HasPrefix(filepath.Base(path), "native"))) {
					found := false
					for _, format := range RuntimeDiagnostics.formats {
						if format.source == source {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("%s missing persisted diagnostic format: %q", fset.Position(literal.Pos()), source)
					}
				}
				if !reflect.DeepEqual(directive.FindAllString(source, -1), directive.FindAllString(T(Chinese, source), -1)) {
					t.Errorf("%s changed format arguments: %q", fset.Position(literal.Pos()), source)
				}
				return true
			})
		}
	}
}
