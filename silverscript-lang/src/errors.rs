use kaspa_txscript::script_builder::ScriptBuilderError;
use thiserror::Error;

use crate::parser::Rule;
use crate::span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("parse error: {0}")]
    Parse(#[from] pest::error::Error<Rule>),
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
    #[error("{source}")]
    Context {
        #[source]
        source: Box<CompilerError>,
        span: ErrorSpan,
    },
}

impl CompilerError {
    pub fn kind(&self) -> &CompilerError {
        self.base()
    }

    pub fn into_kind(self) -> CompilerError {
        self.into_base()
    }

    pub fn base(&self) -> &Self {
        let mut current = self;
        while let Self::Context { source, .. } = current {
            current = source;
        }
        current
    }

    pub fn into_base(self) -> Self {
        let mut current = self;
        while let Self::Context { source, .. } = current {
            current = *source;
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
        if self.span().is_some() || matches!(self.base(), Self::Parse(_)) {
            return self;
        }
        Self::Context { source: Box::new(self), span: ErrorSpan { start: span.start(), end: span.end() } }
    }
}
