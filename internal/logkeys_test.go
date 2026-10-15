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
//
// The check covers direct zap.<Ctor>("key", …) calls with a literal key, the
// only form this module uses. It does not see an aliased zap import, a key
// held in a constant, or the sugared logger's key-value pairs.
var reservedLogKeys = map[string]string{
	"event":  "",    // never as a top-level field
	"status": "Int", // only the HTTP status code
}

func TestLogFieldsKeepTheIndexMappingTypes(t *testing.T) {
	fset := token.NewFileSet()
	// The module root, so cmd/ is covered as well as internal/.
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || !isProductionGoFile(path, d) {
			return skipFixtures(d, err)
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ctor, key, ok := zapField(call); ok {
				if allowed, reserved := reservedLogKeys[key]; reserved && ctor != allowed {
					t.Errorf("%s: zap.%s(%q) conflicts with the Elasticsearch mapping of %q",
						fset.Position(call.Pos()), ctor, key, key)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func isProductionGoFile(path string, d fs.DirEntry) bool {
	return !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// skipFixtures passes walk errors through and skips directories whose Go files
// are not compiled into the service.
func skipFixtures(d fs.DirEntry, err error) error {
	if err == nil && d.IsDir() && (d.Name() == "testdata" || d.Name() == "vendor") {
		return fs.SkipDir
	}
	return err
}

// zapField reports the constructor and literal key of a zap.<Ctor>("key", …)
// call, such as "String" and "status".
func zapField(call *ast.CallExpr) (ctor, key string, ok bool) {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel || len(call.Args) == 0 {
		return "", "", false
	}
	if pkg, isIdent := sel.X.(*ast.Ident); !isIdent || pkg.Name != "zap" {
		return "", "", false
	}
	lit, isLit := call.Args[0].(*ast.BasicLit)
	if !isLit || lit.Kind != token.STRING {
		return "", "", false
	}
	key, err := strconv.Unquote(lit.Value)
	return sel.Sel.Name, key, err == nil
}
