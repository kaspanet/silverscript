use silverscript_lang::ast::parse_contract_ast;

#[test]
fn tutorial_contract_examples_parse() {
    let markdown = include_str!("../../TUTORIAL.md");
    let blocks = extract_code_blocks(markdown, "javascript");
    assert!(!blocks.is_empty(), "no contract examples found in TUTORIAL.md");

    for (index, snippet) in blocks {
        let source = wrap_snippet(&snippet);
        if let Err(err) = parse_contract_ast(&source) {
            panic!("tutorial example #{index} failed to parse: {err}\n--- snippet ---\n{snippet}\n--- wrapped source ---\n{source}");
        }
    }
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
        out.push_str("    entrypoint function main() {\n");
        out.push_str("    }\n");
        out.push_str("}\n");
        return out;
    }

    if looks_like_contract_item(rest) {
        out.push_str(&indent(rest, 4));
        if !rest.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("}\n");
        return out;
    }

    out.push_str("    entrypoint function main() {\n");
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

    line.starts_with("entrypoint function")
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
