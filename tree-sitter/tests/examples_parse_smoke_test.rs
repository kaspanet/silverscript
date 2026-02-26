use std::fs;
use std::path::{Path, PathBuf};

use tree_sitter::Parser;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("silverscript-lang").join("tests").join("examples")
}

#[test]
// note: tree-sitter parse "my-file.sil" produces more descriptive outputs when errored but is heavier to run
fn parses_all_examples_without_errors() {
    let examples_dir = examples_dir();
    assert!(examples_dir.is_dir(), "examples directory not found: {}", examples_dir.display());

    let mut example_files = fs::read_dir(&examples_dir)
        .expect("failed to read examples directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sil"))
        .collect::<Vec<_>>();

    example_files.sort();
    assert!(!example_files.is_empty(), "no .sil files found in {}", examples_dir.display());

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_silverscript::LANGUAGE.into()).expect("failed to load tree-sitter-silverscript grammar");

    let mut failures = Vec::new();

    for file in example_files {
        let source = match fs::read_to_string(&file) {
            Ok(source) => source,
            Err(err) => {
                panic!("{}: failed to read ({err})", file.display());
            }
        };

        let Some(tree) = parser.parse(&source, None) else {
            failures.push(format!("{}: parser returned no tree", file.display()));
            continue;
        };

        if tree.root_node().has_error() {
            failures.push(format!("{}: parse tree contains syntax errors", file.display()));
        }
    }

    assert!(failures.is_empty(), "{} example file(s) failed to parse:\n{}", failures.len(), failures.join("\n"));
}
