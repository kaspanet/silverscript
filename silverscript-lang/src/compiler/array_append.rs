use super::*;
use crate::ast::{ConstantAst, ContractAst, ContractFieldAst, Expr, ExprKind, FunctionAst, StateFieldExpr, Statement};
use crate::compiler::infer_array::infer_expr_type;

pub(super) fn lower_array_appends<'i>(
    contract: &ContractAst<'i>,
    constant_values: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions_by_name = contract.functions.iter().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let mut top_level_types = contract.params.iter().map(|param| (param.name.clone(), param.type_ref.clone())).collect::<TypeMap>();

    let mut constants = Vec::with_capacity(contract.constants.len());
    for constant in &contract.constants {
        constants.push(lower_constant(constant, &top_level_types, constant_values, &functions_by_name)?);
        top_level_types.insert(constant.name.clone(), constant.type_ref.clone());
    }

    let mut fields = Vec::with_capacity(contract.fields.len());
    for field in &contract.fields {
        fields.push(lower_contract_field(field, &top_level_types, constant_values, &functions_by_name)?);
        top_level_types.insert(field.name.clone(), field.type_ref.clone());
    }

    let functions = contract
        .functions
        .iter()
        .map(|function| lower_function(function, &top_level_types, constant_values, &functions_by_name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ContractAst { fields, constants, functions, ..contract.clone() })
}

fn lower_contract_field<'i>(
    field: &ContractFieldAst<'i>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<ContractFieldAst<'i>, CompilerError> {
    Ok(ContractFieldAst { expr: lower_expr(&field.expr, types, constants, functions)?, ..field.clone() })
}

fn lower_constant<'i>(
    constant: &ConstantAst<'i>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<ConstantAst<'i>, CompilerError> {
    Ok(ConstantAst { expr: lower_expr(&constant.expr, types, constants, functions)?, ..constant.clone() })
}

fn lower_function<'i>(
    function: &FunctionAst<'i>,
    top_level_types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut types = top_level_types.clone();
    types.extend(function.params.iter().map(|param| (param.name.clone(), param.type_ref.clone())));
    Ok(FunctionAst { body: lower_block(&function.body, &mut types, constants, functions)?, ..function.clone() })
}

fn lower_block<'i>(
    statements: &[Statement<'i>],
    types: &mut TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let mut lowered = Vec::with_capacity(statements.len());
    for statement in statements {
        lowered.push(lower_statement(statement, types, constants, functions)?);
    }
    Ok(lowered)
}

fn lower_statement<'i>(
    statement: &Statement<'i>,
    types: &mut TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Statement<'i>, CompilerError> {
    match statement {
        Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
            let lowered = Statement::VariableDefinition {
                type_ref: type_ref.clone(),
                modifiers: modifiers.clone(),
                name: name.clone(),
                expr: expr.as_ref().map(|expr| lower_expr(expr, types, constants, functions)).transpose()?,
                span: *span,
                type_span: *type_span,
                modifier_spans: modifier_spans.clone(),
                name_span: *name_span,
            };
            types.insert(name.clone(), type_ref.clone());
            Ok(lowered)
        }
        Statement::TupleAssignment {
            left_type_ref,
            left_name,
            right_type_ref,
            right_name,
            expr,
            span,
            left_type_span,
            left_name_span,
            right_type_span,
            right_name_span,
        } => {
            let lowered = Statement::TupleAssignment {
                left_type_ref: left_type_ref.clone(),
                left_name: left_name.clone(),
                right_type_ref: right_type_ref.clone(),
                right_name: right_name.clone(),
                expr: lower_expr(expr, types, constants, functions)?,
                span: *span,
                left_type_span: *left_type_span,
                left_name_span: *left_name_span,
                right_type_span: *right_type_span,
                right_name_span: *right_name_span,
            };
            types.insert(left_name.clone(), left_type_ref.clone());
            types.insert(right_name.clone(), right_type_ref.clone());
            Ok(lowered)
        }
        Statement::FunctionCall { name, args, span, name_span } => Ok(Statement::FunctionCall {
            name: name.clone(),
            args: args.iter().map(|arg| lower_expr(arg, types, constants, functions)).collect::<Result<Vec<_>, _>>()?,
            span: *span,
            name_span: *name_span,
        }),
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
            let lowered_args = args.iter().map(|arg| lower_expr(arg, types, constants, functions)).collect::<Result<Vec<_>, _>>()?;
            for binding in bindings {
                types.insert(binding.name.clone(), binding.type_ref.clone());
            }
            Ok(Statement::FunctionCallAssign {
                bindings: bindings.clone(),
                name: name.clone(),
                args: lowered_args,
                span: *span,
                name_span: *name_span,
            })
        }
        Statement::StateFunctionCallAssign { target_struct, bindings, name, args, span, name_span } => {
            let lowered_args = args.iter().map(|arg| lower_expr(arg, types, constants, functions)).collect::<Result<Vec<_>, _>>()?;
            for binding in bindings {
                types.insert(binding.name.clone(), binding.type_ref.clone());
            }
            Ok(Statement::StateFunctionCallAssign {
                target_struct: target_struct.clone(),
                bindings: bindings.clone(),
                name: name.clone(),
                args: lowered_args,
                span: *span,
                name_span: *name_span,
            })
        }
        Statement::StructDestructure { struct_name, bindings, expr, span } => {
            let lowered_expr = lower_expr(expr, types, constants, functions)?;
            for binding in bindings {
                types.insert(binding.name.clone(), binding.type_ref.clone());
            }
            Ok(Statement::StructDestructure {
                struct_name: struct_name.clone(),
                bindings: bindings.clone(),
                expr: lowered_expr,
                span: *span,
            })
        }
        Statement::Assign { name, expr, span, name_span } => Ok(Statement::Assign {
            name: name.clone(),
            expr: lower_expr(expr, types, constants, functions)?,
            span: *span,
            name_span: *name_span,
        }),
        Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => Ok(Statement::TimeOp {
            tx_var: *tx_var,
            expr: lower_expr(expr, types, constants, functions)?,
            message: message.clone(),
            span: *span,
            tx_var_span: *tx_var_span,
            message_span: *message_span,
        }),
        Statement::Require { expr, message, span, message_span } => Ok(Statement::Require {
            expr: lower_expr(expr, types, constants, functions)?,
            message: message.clone(),
            span: *span,
            message_span: *message_span,
        }),
        Statement::Block { body, span } => {
            let mut block_types = types.clone();
            Ok(Statement::Block { body: lower_block(body, &mut block_types, constants, functions)?, span: *span })
        }
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
            let condition = lower_expr(condition, types, constants, functions)?;
            let mut then_types = types.clone();
            let then_branch = lower_block(then_branch, &mut then_types, constants, functions)?;
            let else_branch = if let Some(branch) = else_branch {
                let mut else_types = types.clone();
                Some(lower_block(branch, &mut else_types, constants, functions)?)
            } else {
                None
            };
            Ok(Statement::If { condition, then_branch, else_branch, span: *span, then_span: *then_span, else_span: *else_span })
        }
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
            let start = lower_expr(start, types, constants, functions)?;
            let end = lower_expr(end, types, constants, functions)?;
            let max_iterations = lower_expr(max_iterations, types, constants, functions)?;
            let mut body_types = types.clone();
            body_types.insert(ident.clone(), TypeRef { base: TypeBase::Int, array_dims: Vec::new() });
            let body = lower_block(body, &mut body_types, constants, functions)?;
            Ok(Statement::For {
                ident: ident.clone(),
                start,
                end,
                max_iterations,
                body,
                span: *span,
                ident_span: *ident_span,
                body_span: *body_span,
            })
        }
        Statement::Return { exprs, span } => Ok(Statement::Return {
            exprs: exprs.iter().map(|expr| lower_expr(expr, types, constants, functions)).collect::<Result<Vec<_>, _>>()?,
            span: *span,
        }),
        Statement::Console { args, span } => Ok(Statement::Console {
            args: args.iter().map(|arg| lower_expr(arg, types, constants, functions)).collect::<Result<Vec<_>, _>>()?,
            span: *span,
        }),
    }
}

fn lower_expr<'i>(
    expr: &Expr<'i>,
    types: &TypeMap,
    constants: &HashMap<String, Expr<'i>>,
    functions: &HashMap<String, &FunctionAst<'i>>,
) -> Result<Expr<'i>, CompilerError> {
    let span = expr.span;
    match &expr.kind {
        ExprKind::Append { source, args, .. } => {
            let source_type = infer_expr_type(source, types, constants, functions)
                .ok_or_else(|| CompilerError::Unsupported("cannot determine append source type".to_string()))?;
            let mut appended_type = source_type
                .array_element_type()
                .ok_or_else(|| CompilerError::Unsupported("append target must be an array".to_string()))?;
            appended_type.array_dims.push(ArrayDim::Fixed(args.len()));
            Ok(Expr::new(
                ExprKind::Binary {
                    op: BinaryOp::Add,
                    left: Box::new(lower_expr(source, types, constants, functions)?),
                    right: Box::new(Expr::new(
                        ExprKind::Array {
                            type_ref: appended_type,
                            values: args
                                .iter()
                                .map(|arg| lower_expr(arg, types, constants, functions))
                                .collect::<Result<Vec<_>, _>>()?,
                        },
                        span::Span::default(),
                    )),
                },
                span,
            ))
        }
        ExprKind::Array { type_ref, values } => Ok(Expr::new(
            ExprKind::Array {
                type_ref: type_ref.clone(),
                values: values.iter().map(|value| lower_expr(value, types, constants, functions)).collect::<Result<Vec<_>, _>>()?,
            },
            span,
        )),
        ExprKind::Call { name, args, name_span } => Ok(Expr::new(
            ExprKind::Call {
                name: name.clone(),
                args: args.iter().map(|arg| lower_expr(arg, types, constants, functions)).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::New { name, args, name_span } => Ok(Expr::new(
            ExprKind::New {
                name: name.clone(),
                args: args.iter().map(|arg| lower_expr(arg, types, constants, functions)).collect::<Result<Vec<_>, _>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(lower_expr(source, types, constants, functions)?),
                index: Box::new(lower_expr(index, types, constants, functions)?),
                part: *part,
                span: *split_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(lower_expr(source, types, constants, functions)?),
                start: Box::new(lower_expr(start, types, constants, functions)?),
                end: Box::new(lower_expr(end, types, constants, functions)?),
                span: *slice_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(lower_expr(source, types, constants, functions)?),
                index: Box::new(lower_expr(index, types, constants, functions)?),
            },
            span,
        )),
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op: *op, expr: Box::new(lower_expr(expr, types, constants, functions)?) }, span))
        }
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op: *op,
                left: Box::new(lower_expr(left, types, constants, functions)?),
                right: Box::new(lower_expr(right, types, constants, functions)?),
            },
            span,
        )),
        ExprKind::Ternary { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::Ternary {
                condition: Box::new(lower_expr(condition, types, constants, functions)?),
                then_expr: Box::new(lower_expr(then_expr, types, constants, functions)?),
                else_expr: Box::new(lower_expr(else_expr, types, constants, functions)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::Introspection {
                kind: *kind,
                index: Box::new(lower_expr(index, types, constants, functions)?),
                field_span: *field_span,
            },
            span,
        )),
        ExprKind::StructLiteral { name, fields, name_span } => Ok(Expr::new(
            ExprKind::StructLiteral {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|field| {
                        Ok(StateFieldExpr {
                            name: field.name.clone(),
                            expr: lower_expr(&field.expr, types, constants, functions)?,
                            span: field.span,
                            name_span: field.name_span,
                        })
                    })
                    .collect::<Result<Vec<_>, CompilerError>>()?,
                name_span: *name_span,
            },
            span,
        )),
        ExprKind::FieldAccess { source, field, field_span } => Ok(Expr::new(
            ExprKind::FieldAccess {
                source: Box::new(lower_expr(source, types, constants, functions)?),
                field: field.clone(),
                field_span: *field_span,
            },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Ok(Expr::new(
            ExprKind::UnarySuffix {
                source: Box::new(lower_expr(source, types, constants, functions)?),
                kind: *kind,
                span: *suffix_span,
            },
            span,
        )),
        _ => Ok(expr.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{BinaryOp, parse_contract_ast, parse_type_ref};

    #[test]
    fn append_lowering_uses_local_type_for_the_synthesized_fixed_array() {
        let source = r#"
            contract Arrays() {
                entry main() {
                    int[] values = int[]{1};
                    int[] result = values.append(2, 3);
                    require(result.length == 3);
                }
            }
        "#;
        let contract = parse_contract_ast(source).expect("contract should parse");
        let lowered = lower_array_appends(&contract, &HashMap::new()).expect("append should lower");
        let Statement::VariableDefinition { expr: Some(expr), .. } = &lowered.functions[0].body[1] else {
            panic!("expected the result variable definition");
        };
        let ExprKind::Binary { op: BinaryOp::Add, right, .. } = &expr.kind else {
            panic!("append should lower to addition");
        };
        let ExprKind::Array { type_ref, values } = &right.kind else {
            panic!("append arguments should lower to an array");
        };

        assert_eq!(type_ref, &parse_type_ref("int[2]").unwrap());
        assert_eq!(values.len(), 2);
    }
}
