use silverscript_lang::ast::{ArrayDim, Expr, TypeBase, TypeRef, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

#[test]
fn tutorial_contract_examples_parse() {
    let markdown = include_str!("../../docs/TUTORIAL.md");
    let blocks = extract_code_blocks(markdown, "javascript");
    assert!(!blocks.is_empty(), "no contract examples found in docs/TUTORIAL.md");

    for (index, snippet) in blocks {
        let source = wrap_snippet(&snippet);
        if let Err(err) = parse_contract_ast(&source) {
            panic!("tutorial example #{index} failed to parse: {err}\n--- snippet ---\n{snippet}\n--- wrapped source ---\n{source}");
        }
    }
}

#[test]
fn tutorial_examples_compile() {
    let markdown = include_str!("../../docs/TUTORIAL.md");
    let blocks = extract_code_blocks(markdown, "javascript");
    assert!(!blocks.is_empty(), "no contract examples found in docs/TUTORIAL.md");

    for (index, snippet) in blocks {
        let source = wrap_snippet(&snippet);
        let contract = parse_contract_ast(&source).unwrap_or_else(|err| {
            panic!("tutorial example #{index} failed to parse before compilation: {err}\n--- snippet ---\n{snippet}")
        });
        let constructor_args = contract
            .params
            .iter()
            .map(|param| dummy_value(&param.type_ref))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|err| panic!("tutorial example #{index} constructor arguments could not be generated: {err}"));
        if let Err(err) = compile_contract(&source, &constructor_args, CompileOptions::default()) {
            panic!("tutorial example #{index} failed to compile: {err}\n--- snippet ---\n{snippet}\n--- wrapped source ---\n{source}");
        }
    }
}

fn dummy_value(type_ref: &TypeRef) -> Result<Expr<'static>, String> {
    if type_ref.is_array() {
        let length = match type_ref.array_size() {
            Some(ArrayDim::Fixed(length)) => *length,
            Some(ArrayDim::Dynamic) => 0,
            Some(ArrayDim::Constant(name)) => return Err(format!("array size constant '{name}' is unsupported in tutorial tests")),
            Some(ArrayDim::Inferred) | None => return Err(format!("cannot generate a value for {}", type_ref.type_name())),
        };
        let element_type = type_ref.array_element_type().ok_or_else(|| format!("invalid array type {}", type_ref.type_name()))?;
        let values = (0..length).map(|_| dummy_value(&element_type)).collect::<Result<Vec<_>, _>>()?;
        return Ok(Expr::array(type_ref.clone(), values));
    }

    Ok(match &type_ref.base {
        TypeBase::Int => Expr::int(0),
        TypeBase::Temporal => Expr::temporal(kaspa_txscript::LOCK_TIME_THRESHOLD as i64),
        TypeBase::Bool => Expr::bool(false),
        TypeBase::Byte => Expr::byte(0),
        TypeBase::String => Expr::string(String::new()),
        TypeBase::Pubkey => Expr::bytes(vec![0; 32]),
        TypeBase::Sig => Expr::bytes(vec![0; 65]),
        TypeBase::Datasig => Expr::bytes(vec![0; 64]),
        TypeBase::Tuple(_) | TypeBase::Custom(_) => return Err(format!("cannot generate a value for {}", type_ref.type_name())),
    })
}

fn extract_code_blocks(markdown: &str, language: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut current_lang = None::<String>;
    let mut current = String::new();
    let mut block_index = 0usize;

    for line in markdown.lines() {
        if let Some(lang) = line.strip_prefix("```") {
            if !in_block {
                in_block = true;
                block_index += 1;
                current_lang = Some(lang.trim().to_string());
                current.clear();
            } else {
                if current_lang.as_deref() == Some(language) {
                    blocks.push((block_index, current.trim_end().to_string()));
                }
                in_block = false;
                current_lang = None;
            }
            continue;
        }

        if in_block {
            current.push_str(line);
            current.push('\n');
        }
    }

    blocks
}

fn wrap_snippet(snippet: &str) -> String {
    let trimmed = snippet.trim();
    if looks_like_contract_definition(trimmed) {
        return trimmed.to_string();
    }

    let (pragma_line, rest) = split_pragma(trimmed);
    let rest = rest.trim();

    let mut out = String::new();
    if let Some(pragma) = pragma_line {
        out.push_str(pragma);
        out.push('\n');
    } else {
        out.push_str("pragma silverscript ^0.1.0;\n");
    }

    out.push('\n');
    out.push_str("contract TutorialSnippet() {\n");

    if rest.is_empty() {
        out.push_str("    entry main() {\n");
        out.push_str("    }\n");
        out.push_str("}\n");
        return out;
    }

    if looks_like_contract_item(rest) {
        out.push_str(&indent(rest, 4));
        if !rest.ends_with('\n') {
            out.push('\n');
        }
        if !rest.lines().any(|line| line.trim_start().starts_with("entry ")) {
            out.push_str("    entry main() {\n");
            out.push_str("        require(true);\n");
            out.push_str("    }\n");
        }
        out.push_str("}\n");
        return out;
    }

    out.push_str("    entry main() {\n");
    out.push_str(&indent(rest, 8));
    if !rest.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

fn looks_like_contract_definition(snippet: &str) -> bool {
    let mut in_block_comment = false;
    for line in snippet.lines() {
        let trimmed = line.trim();
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("pragma silverscript") {
            continue;
        }
        if trimmed.starts_with("contract ") {
            return true;
        }
    }
    false
}

fn split_pragma(snippet: &str) -> (Option<&str>, String) {
    let mut lines = snippet.lines();
    let Some(first) = lines.next() else {
        return (None, String::new());
    };
    if first.trim_start().starts_with("pragma silverscript") {
        return (Some(first.trim_end()), lines.collect::<Vec<_>>().join("\n"));
    }
    (None, snippet.to_string())
}

fn looks_like_contract_item(snippet: &str) -> bool {
    let mut in_block_comment = false;
    let mut first_code_line = None::<String>;

    for line in snippet.lines() {
        let trimmed = line.trim();
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        first_code_line = Some(trimmed.to_string());
        break;
    }

    let Some(line) = first_code_line else {
        return false;
    };

    line.starts_with("entry ")
        || line.starts_with("function ")
        || line.starts_with("int constant ")
        || line.starts_with("bool constant ")
        || line.starts_with("string constant ")
        || line.starts_with("bytes constant ")
        || line.starts_with("pubkey constant ")
        || line.starts_with("sig constant ")
        || line.starts_with("datasig constant ")
}

fn indent(text: &str, spaces: usize) -> String {
    let padding = " ".repeat(spaces);
    text.lines().map(|line| if line.is_empty() { line.to_string() } else { format!("{padding}{line}") }).collect::<Vec<_>>().join("\n")
}
