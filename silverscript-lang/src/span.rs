use std::fmt;
use std::ops::Deref;

use pest::Span as PestSpan;
use serde::Serialize;
use serde::Serializer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span<'i>(PestSpan<'i>);

impl<'i> Span<'i> {
    pub fn new(input: &'i str, start: usize, end: usize) -> Option<Self> {
        PestSpan::new(input, start, end).map(Span)
    }

    pub fn join(&self, other: &Span<'i>) -> Span<'i> {
        let input = self.get_input();
        let start = self.start().min(other.start());
        let end = self.end().max(other.end());
        Span::new(input, start, end).unwrap_or(*self)
    }
}

impl<'i> Default for Span<'i> {
    fn default() -> Self {
        Span(PestSpan::new("", 0, 0).expect("synthetic span"))
    }
}

impl<'i> From<PestSpan<'i>> for Span<'i> {
    fn from(span: PestSpan<'i>) -> Self {
        Span(span)
    }
}

impl<'i> Deref for Span<'i> {
    type Target = PestSpan<'i>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'i> fmt::Display for Span<'i> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = self.as_str();
        if source.is_empty() { f.write_str("<synthetic>") } else { f.write_str(source) }
    }
}

// serde serialize becomes display
impl<'i> Serialize for Span<'i> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub trait SpanUtils {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn contains(&self, offset: usize) -> bool;
}

impl<'i> SpanUtils for Span<'i> {
    fn len(&self) -> usize {
        self.end().saturating_sub(self.start())
    }

    fn contains(&self, offset: usize) -> bool {
        offset >= self.start() && offset < self.end()
    }
}

pub fn join<'i>(left: &Span<'i>, right: &Span<'i>) -> Span<'i> {
    left.join(right)
}
