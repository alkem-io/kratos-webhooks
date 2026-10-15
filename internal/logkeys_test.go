package internal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Logstash decodes every JSON log line to the top level of the event and
// writes it to logstash-output-alkemio-kratos-webhooks, where each field keeps
// the type it was first indexed with. Two names are already taken there:
//
//   - "event" is Filebeat's ECS object, so any concrete value is rejected
//     ("object mapping for [event] tried to parse field [event] as object").
//   - "status" is a long, set by the request logger's HTTP status code, so a
//     string such as "success" is rejected ("failed to parse field [status]
//     of type [long]").
//
// A rejected line is dropped from Elasticsearch silently. Use a different key
// (for example "outcome" or "action") for string values.
var reservedLogKeys = map[string]string{
	"event":  "",    // never as a top-level field
	"status": "Int", // only the HTTP status code
}

func TestLogFieldsKeepTheIndexMappingTypes(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "zap" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, _ := strconv.Unquote(lit.Value)
			allowed, reserved := reservedLogKeys[key]
			if reserved && sel.Sel.Name != allowed {
				t.Errorf("%s: zap.%s(%q) conflicts with the Elasticsearch mapping of %q",
					fset.Position(call.Pos()), sel.Sel.Name, key, key)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
