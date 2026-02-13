use kaspa_txscript::script_builder::ScriptBuilderError;
use thiserror::Error;

pub use crate::diagnostic::{ErrorSpan, ParseDiagnostic, ParseDiagnosticLabel, ParseDisplayLocation, ParseErrorInterpretation};
use crate::span;

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("parse error: {0}")]
    Parse(#[from] ParseDiagnostic),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
    #[error("invalid literal: {0}")]
    InvalidLiteral(String),
    #[error("undefined identifier: {0}")]
    UndefinedIdentifier(String),
    #[error("cyclic identifier reference: {0}")]
    CyclicIdentifier(String),
    #[error("script build error: {0}")]
    ScriptBuild(#[from] ScriptBuilderError),
    // QUESTION: not entierly sure about this pattern
    #[error("{source}")]
    Context {
        #[source]
        source: Box<CompilerError>,
        span: ErrorSpan,
    },
}

impl CompilerError {
    pub fn root(&self) -> &CompilerError {
        let mut current = self;
        while let Self::Context { source, .. } = current {
            current = source;
        }
        current
    }

    pub fn span(&self) -> Option<ErrorSpan> {
        match self {
            Self::Context { span, .. } => Some(*span),
            _ => None,
        }
    }

    pub fn with_span(self, span: &span::Span<'_>) -> Self {
        if self.span().is_some() || matches!(self.root(), Self::Parse(_)) {
            return self;
        }
        Self::Context { source: Box::new(self), span: ErrorSpan { start: span.start(), end: span.end() } }
    }
}
