use pest::Parser;
use pest::iterators::Pairs;
use pest_derive::Parser;

use crate::errors::ParseDiagnostic;

#[derive(Parser)]
#[grammar = "silverscript.pest"]
pub struct SilverScriptParser;

pub fn parse_source_file(input: &str) -> Result<Pairs<'_, Rule>, ParseDiagnostic> {
    pest::set_error_detail(true);
    SilverScriptParser::parse(Rule::source_file, input).map_err(|err| crate::diagnostic::interpret_parse_error(input, &err))
}

pub fn parse_expression(input: &str) -> Result<Pairs<'_, Rule>, ParseDiagnostic> {
    pest::set_error_detail(true);
    SilverScriptParser::parse(Rule::expression, input).map_err(|err| crate::diagnostic::interpret_parse_error(input, &err))
}
