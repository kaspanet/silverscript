use silverscript_lang::debug_info::SourceSpan;

use crate::session::DebugValue;
use crate::util::{decode_i64, encode_hex};

#[derive(Debug, Clone)]
pub struct SourceContextLine {
    pub line: u32,
    pub text: String,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct SourceContext {
    pub lines: Vec<SourceContextLine>,
}

pub fn build_source_context(source_lines: &[String], span: SourceSpan, radius: usize) -> SourceContext {
    let line = span.line.saturating_sub(1) as usize;
    let start = line.saturating_sub(radius);
    let end = (line + radius).min(source_lines.len().saturating_sub(1));

    let mut lines = Vec::new();
    for idx in start..=end {
        let display_line = idx + 1;
        let content = source_lines.get(idx).map(String::as_str).unwrap_or("");
        lines.push(SourceContextLine { line: display_line as u32, text: content.to_string(), is_active: idx == line });
    }

    SourceContext { lines }
}

pub fn format_value(type_name: &str, value: &DebugValue) -> String {
    let element_type = type_name.strip_suffix("[]");
    match (type_name, value) {
        ("int", DebugValue::Int(number)) => number.to_string(),
        ("bool", DebugValue::Bool(value)) => value.to_string(),
        ("string", DebugValue::String(value)) => value.clone(),
        (_, DebugValue::Unknown(reason)) => unavailable_reason(reason),
        (_, DebugValue::Bytes(bytes)) if element_type.is_some() => {
            let element_type = element_type.expect("checked");
            let Some(element_size) = array_element_size(element_type) else {
                return format!("0x{}", encode_hex(bytes));
            };
            if element_size == 0 || bytes.len() % element_size != 0 {
                return format!("0x{}", encode_hex(bytes));
            }

            let mut values: Vec<String> = Vec::new();
            for chunk in bytes.chunks(element_size) {
                let decoded = match element_type {
                    "int" => DebugValue::Int(decode_i64(chunk).unwrap_or(0)),
                    "bool" => DebugValue::Bool(decode_i64(chunk).unwrap_or(0) != 0),
                    _ => DebugValue::Bytes(chunk.to_vec()),
                };
                values.push(format_value(element_type, &decoded));
            }
            format!("[{}]", values.join(", "))
        }
        (_, DebugValue::Bytes(bytes)) => format!("0x{}", encode_hex(bytes)),
        (_, DebugValue::Int(number)) => number.to_string(),
        (_, DebugValue::Bool(value)) => value.to_string(),
        (_, DebugValue::String(value)) => value.clone(),
        (_, DebugValue::Array(values)) => {
            let value_type = element_type.unwrap_or(type_name);
            format!("[{}]", values.iter().map(|v| format_value(value_type, v)).collect::<Vec<_>>().join(", "))
        }
    }
}

fn unavailable_reason(reason: &str) -> String {
    if reason.trim().is_empty() {
        "<unavailable>".to_string()
    } else if reason.contains("failed to compile debug expression")
        || reason.contains("undefined identifier")
        || reason.contains("__arg_")
    {
        "<unavailable: depends on inlined function call internals>".to_string()
    } else if reason.contains("failed to execute shadow script") {
        "<unavailable: runtime evaluation failed>".to_string()
    } else {
        format!("<unavailable: {}>", concise_reason(reason))
    }
}

/// Truncates error messages to 96 chars for display in debugger UI.
fn concise_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let first_line = trimmed.lines().next().unwrap_or(trimmed);
    const MAX_CHARS: usize = 96;
    if first_line.chars().count() <= MAX_CHARS {
        first_line.to_string()
    } else {
        let mut out = String::new();
        for ch in first_line.chars().take(MAX_CHARS) {
            out.push(ch);
        }
        out.push_str("...");
        out
    }
}

fn array_element_size(element_type: &str) -> Option<usize> {
    match element_type {
        "int" => Some(8),
        "bool" => Some(1),
        "byte" => Some(1),
        other => other.strip_prefix("bytes").and_then(|v| v.parse::<usize>().ok()),
    }
}
