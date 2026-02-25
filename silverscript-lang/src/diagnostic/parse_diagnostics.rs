use std::collections::BTreeSet;

use super::parse::{ErrorSpan, ParseDiagnostic, ParseDiagnosticLabel, ParseErrorInterpretation};
use crate::parser::Rule;

const MISSING_SEMICOLON_EXPECTED_TOKENS: &[&str] = &["WHITESPACE", "/*", "//", ";"];

#[derive(Clone, Copy)]
enum SpanStrategy {
    AtFailure,
    PreviousNonWhitespaceOrFailure,
}

impl SpanStrategy {
    fn resolve(self, input: &str, failure_pos: usize) -> ErrorSpan {
        let failure_pos = failure_pos.min(input.len());
        let start = match self {
            Self::AtFailure => failure_pos,
            Self::PreviousNonWhitespaceOrFailure => focused_error_start(input, failure_pos),
        };
        ErrorSpan { start, end: start }
    }
}

#[derive(Clone, Copy)]
struct InterpretationSpec {
    interpretation: ParseErrorInterpretation,
    span_strategy: SpanStrategy,
    expected_tokens_override: Option<&'static [&'static str]>,
    help: Option<&'static str>,
    primary_label: Option<&'static str>,
    notes: &'static [&'static str],
}

const UNCLASSIFIED_SPEC: InterpretationSpec = InterpretationSpec {
    interpretation: ParseErrorInterpretation::Unclassified,
    span_strategy: SpanStrategy::AtFailure,
    expected_tokens_override: None,
    help: None,
    primary_label: None,
    notes: &[],
};

const INTERPRETATION_SPECS: &[InterpretationSpec] = &[
    InterpretationSpec {
        interpretation: ParseErrorInterpretation::MissingSemicolon,
        span_strategy: SpanStrategy::PreviousNonWhitespaceOrFailure,
        expected_tokens_override: Some(MISSING_SEMICOLON_EXPECTED_TOKENS),
        help: Some("statements must end with ';'"),
        primary_label: Some("expected ';' to terminate statement"),
        notes: &[],
    },
    UNCLASSIFIED_SPEC,
];

#[derive(Clone, Copy)]
struct InterpretationHeuristic {
    interpretation: ParseErrorInterpretation,
    matches: fn(&ParseAttemptData) -> bool,
}

const INTERPRETATION_HEURISTICS: &[InterpretationHeuristic] =
    &[InterpretationHeuristic { interpretation: ParseErrorInterpretation::MissingSemicolon, matches: expects_semicolon }];

#[derive(Default)]
struct ParseAttemptData {
    expected_tokens: Vec<String>,
    rules: Vec<Rule>,
}

impl ParseAttemptData {
    fn from_error(err: &pest::error::Error<Rule>) -> Self {
        let Some(attempts) = err.parse_attempts() else {
            return Self::default();
        };

        let expected_tokens = attempts.expected_tokens().into_iter().map(|token| token.to_string()).collect::<Vec<_>>();

        let mut rules = Vec::new();
        for stack in attempts.call_stacks() {
            if let Some(rule) = stack.deepest.get_rule() {
                rules.push(*rule);
            }
            if let Some(rule) = stack.parent {
                rules.push(rule);
            }
        }

        Self { expected_tokens, rules }
    }

    fn expects_token(&self, token: &str) -> bool {
        self.expected_tokens.iter().any(|candidate| candidate == token)
    }

    // remove once used by one of the heuristic matcher
    #[allow(dead_code)]
    fn includes_rule(&self, rule: Rule) -> bool {
        self.rules.contains(&rule)
    }
}

pub(crate) fn interpret_parse_error(input: &str, err: &pest::error::Error<Rule>) -> ParseDiagnostic {
    let failure_pos = error_start_offset(err);
    let attempt_data = ParseAttemptData::from_error(err);
    let interpretation = classify_interpretation(&attempt_data);
    let spec = interpretation_spec(interpretation);
    let span = spec.span_strategy.resolve(input, failure_pos);
    let primary_message = match interpretation {
        ParseErrorInterpretation::Unclassified => err.variant.message().into_owned(),
        _ => "parsing error occurred.".to_owned(),
    };

    let mut diagnostic = ParseDiagnostic::new(interpretation, span, input, primary_message)
        .with_expected_tokens(normalize_expected_tokens(&attempt_data.expected_tokens, spec))
        .with_labels(primary_labels(spec, span))
        .with_notes(spec.notes.iter().map(|note| (*note).to_owned()).collect());
    if let Some(help) = spec.help {
        diagnostic = diagnostic.with_help(help);
    }
    diagnostic
}

fn classify_interpretation(attempt_data: &ParseAttemptData) -> ParseErrorInterpretation {
    INTERPRETATION_HEURISTICS
        .iter()
        .find(|heuristic| (heuristic.matches)(attempt_data))
        .map(|heuristic| heuristic.interpretation)
        .unwrap_or(ParseErrorInterpretation::Unclassified)
}

fn expects_semicolon(attempt_data: &ParseAttemptData) -> bool {
    attempt_data.expects_token(";")
}

fn interpretation_spec(interpretation: ParseErrorInterpretation) -> &'static InterpretationSpec {
    INTERPRETATION_SPECS.iter().find(|spec| spec.interpretation == interpretation).unwrap_or(&UNCLASSIFIED_SPEC)
}

fn normalize_expected_tokens(expected_tokens: &[String], spec: &InterpretationSpec) -> Vec<String> {
    if let Some(tokens) = spec.expected_tokens_override {
        return tokens.iter().map(|token| (*token).to_owned()).collect();
    }

    expected_tokens.iter().map(|token| normalize_token(token)).collect::<BTreeSet<_>>().into_iter().collect()
}

fn primary_labels(spec: &InterpretationSpec, span: ErrorSpan) -> Vec<ParseDiagnosticLabel> {
    spec.primary_label.map(|label| vec![ParseDiagnosticLabel::new(span, label)]).unwrap_or_default()
}

fn normalize_token(token: &str) -> String {
    if token.chars().all(char::is_whitespace) { "WHITESPACE".to_string() } else { token.to_string() }
}

fn error_start_offset(err: &pest::error::Error<Rule>) -> usize {
    match err.location {
        pest::error::InputLocation::Pos(pos) => pos,
        pest::error::InputLocation::Span((start, _)) => start,
    }
}

fn focused_error_start(input: &str, failure_pos: usize) -> usize {
    if is_closing_delimiter_at(input, failure_pos) {
        failure_pos
    } else {
        previous_non_whitespace_offset(input, failure_pos).unwrap_or(failure_pos)
    }
}

fn previous_non_whitespace_offset(input: &str, pos: usize) -> Option<usize> {
    let prefix = input.get(..pos)?;
    prefix.char_indices().rev().find_map(|(idx, ch)| if ch.is_whitespace() { None } else { Some(idx) })
}

fn is_closing_delimiter_at(input: &str, pos: usize) -> bool {
    matches!(input.as_bytes().get(pos), Some(b')' | b']' | b'}'))
}
