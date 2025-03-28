package main

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/analysis/singlechecker"
	"golang.org/x/tools/go/ast/inspector"
)

func run(pass *analysis.Pass) (any, error) {
	check := func(e ast.Expr) {
		switch e.(type) {
		case *ast.CallExpr, *ast.CompositeLit:
			return
		}
		if named, ok := pass.TypesInfo.TypeOf(e).(*types.Named); ok {
			if obj := named.Obj(); obj.Pkg() != nil && obj.Pkg().Path() == "go.sia.tech/core/types" {
				switch name := obj.Name(); name {
				case "StateElement", "ChainIndexElement", "SiacoinElement", "SiafundElement",
					"FileContractElement", "V2FileContractElement", "AttestationElement":
					pass.Reportf(e.Pos(), "shallow copy of %s; use Move, Share, or Copy", name)
				}
			}
		}
	}

	nodeFilter := []ast.Node{
		(*ast.AssignStmt)(nil),
		(*ast.CallExpr)(nil),
		(*ast.CompositeLit)(nil),
	}
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	inspect.Preorder(nodeFilter, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.ASSIGN || node.Tok == token.DEFINE {
				for i := range min(len(node.Lhs), len(node.Rhs)) {
					check(node.Rhs[i])
				}
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				check(arg)
			}
		case *ast.CompositeLit:
			for _, elt := range node.Elts {
				if kve, ok := elt.(*ast.KeyValueExpr); ok {
					check(kve.Value)
				}
			}
		}
	})

	return nil, nil
}

func main() {
	singlechecker.Main(&analysis.Analyzer{
		Name:     "elmo",
		Doc:      "reports implicit StateElement memory management",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      run,
	})
}
