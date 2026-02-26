package tree_sitter_silverscript_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_silverscript "github.com/tree-sitter/tree-sitter-silverscript/bindings/go"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_silverscript.Language())
	if language == nil {
		t.Errorf("Error loading SilverScript grammar")
	}
}
