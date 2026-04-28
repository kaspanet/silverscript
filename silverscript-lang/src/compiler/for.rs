use super::*;
use crate::ast::{ContractAst, Expr, FunctionAst, Statement, TypeBase, TypeRef};
use crate::span;

pub(super) fn lower_for_loops<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let mut lowerer = ForLowerer { fresh_counter: 0, constants };
    let functions = contract.functions.iter().map(|function| lowerer.lower_function(function)).collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst {
        pragma: contract.pragma.clone(),
        name: contract.name.clone(),
        params: contract.params.clone(),
        structs: contract.structs.clone(),
        fields: contract.fields.clone(),
        constants: contract.constants.clone(),
        functions,
        span: contract.span,
        name_span: contract.name_span,
    })
}

struct ForLowerer<'a, 'i> {
    fresh_counter: usize,
    constants: &'a HashMap<String, Expr<'i>>,
}

impl<'a, 'i> ForLowerer<'a, 'i> {
    fn fresh_name(&mut self, ident: &str) -> String {
        let name = format!("__for_{}_{}", self.fresh_counter, ident);
        self.fresh_counter += 1;
        name
    }

    fn lower_function(&mut self, function: &FunctionAst<'i>) -> Result<FunctionAst<'i>, CompilerError> {
        Ok(FunctionAst { body: self.lower_block(&function.body)?, ..function.clone() })
    }

    fn lower_block(&mut self, statements: &[Statement<'i>]) -> Result<Vec<Statement<'i>>, CompilerError> {
        let mut lowered = Vec::new();
        for statement in statements {
            lowered.extend(self.lower_statement(statement)?);
        }
        Ok(lowered)
    }

    fn lower_statement(&mut self, statement: &Statement<'i>) -> Result<Vec<Statement<'i>>, CompilerError> {
        match statement {
            Statement::Block { body, span } => Ok(vec![Statement::Block { body: self.lower_block(body)?, span: *span }]),
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => Ok(vec![Statement::If {
                condition: condition.clone(),
                then_branch: self.lower_block(then_branch)?,
                else_branch: else_branch.as_ref().map(|branch| self.lower_block(branch)).transpose()?,
                span: *span,
                then_span: *then_span,
                else_span: *else_span,
            }]),
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                self.lower_for_statement(ident, start, end, max_iterations, body, *span, *ident_span, *body_span)
            }
            _ => Ok(vec![statement.clone()]),
        }
    }

    fn lower_for_statement(
        &mut self,
        ident: &str,
        start: &Expr<'i>,
        end: &Expr<'i>,
        max_iterations: &Expr<'i>,
        body: &[Statement<'i>],
        span: span::Span<'i>,
        ident_span: span::Span<'i>,
        body_span: span::Span<'i>,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let max_iterations = match eval_const_int(max_iterations, self.constants) {
            Ok(value) => value,
            Err(CompilerError::InvalidLiteral(message)) => return Err(CompilerError::InvalidLiteral(message)),
            Err(_) => return Err(CompilerError::Unsupported("for loop max iterations must be a compile-time integer".to_string())),
        };
        if max_iterations < 0 {
            return Err(CompilerError::Unsupported("for loop max iterations must be a non-negative compile-time integer".to_string()));
        }

        if let (Ok(start_value), Ok(end_value)) = (eval_const_int(start, self.constants), eval_const_int(end, self.constants)) {
            return self.lower_constant_for_statement(ident, start_value, end_value, max_iterations as usize, body, span, ident_span);
        }

        let lowered_body = self.lower_block(body)?;
        let accumulator_name = self.fresh_name(ident);
        let accumulator_type_ref = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
        let mut lowered = vec![Statement::VariableDefinition {
            type_ref: accumulator_type_ref.clone(),
            modifiers: Vec::new(),
            name: accumulator_name.clone(),
            expr: Some(start.clone()),
            span,
            type_span: ident_span,
            modifier_spans: Vec::new(),
            name_span: ident_span,
        }];

        for _ in 0..(max_iterations as usize) {
            let condition = Expr::new(
                ExprKind::Binary {
                    op: BinaryOp::Lt,
                    left: Box::new(Expr::identifier(&accumulator_name)),
                    right: Box::new(end.clone()),
                },
                span,
            );
            let mut then_branch = vec![Statement::VariableDefinition {
                type_ref: accumulator_type_ref.clone(),
                modifiers: Vec::new(),
                name: ident.to_string(),
                expr: Some(Expr::identifier(&accumulator_name)),
                span,
                type_span: ident_span,
                modifier_spans: Vec::new(),
                name_span: ident_span,
            }];
            then_branch.extend(lowered_body.clone());
            then_branch.push(Statement::Assign {
                name: accumulator_name.clone(),
                expr: Expr::new(
                    ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::identifier(ident)), right: Box::new(Expr::int(1)) },
                    span,
                ),
                span,
                name_span: ident_span,
            });
            lowered.push(Statement::If { condition, then_branch, else_branch: None, span, then_span: body_span, else_span: None });
        }

        Ok(lowered)
    }

    fn lower_constant_for_statement(
        &mut self,
        ident: &str,
        start: i64,
        end: i64,
        max_iterations: usize,
        body: &[Statement<'i>],
        span: span::Span<'i>,
        ident_span: span::Span<'i>,
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let lowered_body = self.lower_block(body)?;
        let loop_var_type_ref = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
        let mut lowered = Vec::new();

        for iteration in 0..max_iterations {
            let value = start + iteration as i64;
            if value >= end {
                break;
            }
            let mut then_branch = vec![Statement::VariableDefinition {
                type_ref: loop_var_type_ref.clone(),
                modifiers: Vec::new(),
                name: ident.to_string(),
                expr: Some(Expr::int(value)),
                span,
                type_span: ident_span,
                modifier_spans: Vec::new(),
                name_span: ident_span,
            }];
            then_branch.extend(lowered_body.clone());
            lowered.push(Statement::Block { body: then_branch, span });
        }

        Ok(lowered)
    }
}
