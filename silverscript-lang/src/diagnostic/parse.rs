use std::fmt;

use pest::Position;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseErrorInterpretation {
    MissingSemicolon,
    MissingColon,
    Unclassified,
}

impl ParseErrorInterpretation {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingSemicolon => "missing_semicolon",
            Self::MissingColon => "missing_colon",
            Self::Unclassified => "parse_error",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "missing_semicolon" => Some(Self::MissingSemicolon),
            "missing_colon" => Some(Self::MissingColon),
            "parse_error" => Some(Self::Unclassified),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnosticLabel {
    span: ErrorSpan,
    message: String,
}

impl ParseDiagnosticLabel {
    pub fn new(span: ErrorSpan, message: impl Into<String>) -> Self {
        Self { span, message: message.into() }
    }

    pub fn span(&self) -> ErrorSpan {
        self.span
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDisplayLocation {
    line: usize,
    column: usize,
    line_text: String,
}

impl ParseDisplayLocation {
    pub fn new(line: usize, column: usize, line_text: impl Into<String>) -> Self {
        Self { line, column, line_text: line_text.into() }
    }

    pub fn line(&self) -> usize {
        self.line
    }

    pub fn column(&self) -> usize {
        self.column
    }

    pub fn line_text(&self) -> &str {
        &self.line_text
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnostic {
    interpretation: ParseErrorInterpretation,
    span: ErrorSpan,
    primary_message: String,
    expected_tokens: Vec<String>,
    labels: Vec<ParseDiagnosticLabel>,
    help: Option<String>,
    notes: Vec<String>,
    source_text: Box<str>,
}

impl ParseDiagnostic {
    pub(crate) fn new(
        interpretation: ParseErrorInterpretation,
        span: ErrorSpan,
        source_text: &str,
        primary_message: impl Into<String>,
    ) -> Self {
        Self {
            interpretation,
            span,
            primary_message: primary_message.into(),
            expected_tokens: Vec::new(),
            labels: Vec::new(),
            help: None,
            notes: Vec::new(),
            source_text: source_text.to_owned().into_boxed_str(),
        }
    }

    pub(crate) fn with_expected_tokens(mut self, expected_tokens: Vec<String>) -> Self {
        self.expected_tokens = expected_tokens;
        self
    }

    pub(crate) fn with_labels(mut self, labels: Vec<ParseDiagnosticLabel>) -> Self {
        self.labels = labels;
        self
    }

    pub(crate) fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub(crate) fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }

    pub fn code(&self) -> &'static str {
        self.interpretation.code()
    }

    pub fn interpretation(&self) -> ParseErrorInterpretation {
        self.interpretation
    }

    pub fn span(&self) -> ErrorSpan {
        self.span
    }

    pub fn primary_message(&self) -> &str {
        &self.primary_message
    }

    pub fn expected_tokens(&self) -> &[String] {
        &self.expected_tokens
    }

    pub fn labels(&self) -> &[ParseDiagnosticLabel] {
        &self.labels
    }

    pub fn help(&self) -> Option<&str> {
        self.help.as_deref()
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    pub fn display_location(&self) -> ParseDisplayLocation {
        if self.source_text.is_empty() {
            return ParseDisplayLocation::new(1, 1, String::new());
        }
        let pos = self.span.start.min(self.source_text.len());
        let position = Position::new(&self.source_text, pos).unwrap_or_else(|| Position::from_start(&self.source_text));
        let (line, column) = position.line_col();
        let line_text = position.line_of().lines().next().unwrap_or_default().to_owned();
        ParseDisplayLocation::new(line, column, line_text)
    }
}

// TODO: make the display dumb and:
// * CLI: adapt diagnostic to miette diagnostic
// * LSP: adapt to LSP diagnostic (tower-lsp)
impl fmt::Display for ParseDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = self.display_location();
        let line_digits = location.line().to_string().len();
        let spacing = " ".repeat(line_digits);
        let underline_pad = " ".repeat(location.column().saturating_sub(1));
        writeln!(f, "{spacing}--> {}:{}", location.line(), location.column())?;
        writeln!(f, "{spacing} |")?;
        writeln!(f, "{} | {}", location.line(), location.line_text())?;
        writeln!(f, "{spacing} | {underline_pad}^---")?;
        writeln!(f, "{spacing} |")?;
        writeln!(f, "{spacing} = error: {}", self.primary_message)?;

        if !self.expected_tokens.is_empty() {
            let expected_tokens = self.expected_tokens.iter().map(|token| format_expected_token(token)).collect::<Vec<_>>().join(", ");
            writeln!(f, "{spacing}   note: expected one of tokens: {expected_tokens}")?;
        }
        for note in &self.notes {
            writeln!(f, "{spacing}   note: {note}")?;
        }
        if let Some(help) = &self.help {
            writeln!(f, "{spacing}   help: {help}")?;
        }

        Ok(())
    }
}

fn format_expected_token(token: &str) -> String {
    match token {
        "WHITESPACE" => "WHITESPACE".to_owned(),
        _ => format!("`{token}`"),
    }
}

impl std::error::Error for ParseDiagnostic {}
