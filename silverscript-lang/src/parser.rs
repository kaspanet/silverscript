use pest::error::Error;
use pest::iterators::Pairs;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "silverscript.pest"]
pub struct SilverScriptParser;

pub fn parse_source_file(input: &str) -> Result<Pairs<'_, Rule>, Error<Rule>> {
    SilverScriptParser::parse(Rule::source_file, input)
}

pub fn parse_expression(input: &str) -> Result<Pairs<'_, Rule>, Error<Rule>> {
    SilverScriptParser::parse(Rule::expression, input)
}
