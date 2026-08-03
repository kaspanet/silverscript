use super::*;

pub(crate) fn eval_const_int<'i>(expr: &Expr<'i>, constants: &HashMap<String, Expr<'i>>) -> Result<i64, CompilerError> {
    match &expr.kind {
        ExprKind::Int(value) => Ok(*value),
        ExprKind::DateLiteral(value) => Ok(*value),
        ExprKind::Identifier(name) => match constants.get(name) {
            Some(value) => eval_const_int(value, constants),
            None => Err(CompilerError::Unsupported(format!("'{name}' is not a constant integer"))),
        },
        ExprKind::Unary { op: UnaryOp::Neg, expr } => {
            let value = eval_const_int(expr, constants)?;
            value.checked_neg().ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: -({value})")))
        }
        ExprKind::Unary { .. } => Err(CompilerError::Unsupported("constant expression must evaluate to an integer".to_string())),
        ExprKind::Binary { op, left, right } => {
            let lhs = eval_const_int(left, constants)?;
            let rhs = eval_const_int(right, constants)?;
            match op {
                BinaryOp::Add => lhs
                    .checked_add(rhs)
                    .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} + {rhs}"))),
                BinaryOp::Sub => lhs
                    .checked_sub(rhs)
                    .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} - {rhs}"))),
                BinaryOp::Mul => lhs
                    .checked_mul(rhs)
                    .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} * {rhs}"))),
                BinaryOp::Div => {
                    if rhs == 0 {
                        return Err(CompilerError::InvalidLiteral("division by zero in constant expression".to_string()));
                    }
                    lhs.checked_div(rhs)
                        .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} / {rhs}")))
                }
                BinaryOp::Mod => {
                    if rhs == 0 {
                        return Err(CompilerError::InvalidLiteral("modulo by zero in constant expression".to_string()));
                    }
                    lhs.checked_rem(rhs)
                        .ok_or_else(|| CompilerError::InvalidLiteral(format!("constant integer overflow: {lhs} % {rhs}")))
                }
                _ => Err(CompilerError::Unsupported("constant expression must evaluate to an integer".to_string())),
            }
        }
        _ => Err(CompilerError::Unsupported("constant expression must evaluate to an integer".to_string())),
    }
}

/// Recursively replaces identifiers that refer to known constants, while
/// leaving runtime identifiers intact. This expands references but does not
/// evaluate or fold the resulting expression.
pub(crate) fn resolve_constant_references<'i>(
    expr: Expr<'i>,
    constants: &HashMap<String, Expr<'i>>,
    visiting: &mut HashSet<String>,
) -> Result<Expr<'i>, CompilerError> {
    let Expr { kind, span } = expr;
    match kind {
        ExprKind::Identifier(name) => {
            if let Some(value) = constants.get(&name) {
                if matches!(&value.kind, ExprKind::Identifier(inner) if inner == &name) {
                    return Ok(Expr::new(ExprKind::Identifier(name), span));
                }
                if !visiting.insert(name.clone()) {
                    return Err(CompilerError::CyclicIdentifier(name));
                }
                let resolved = resolve_constant_references(value.clone(), constants, visiting)?;
                visiting.remove(&name);
                Ok(resolved)
            } else {
                Ok(Expr::new(ExprKind::Identifier(name), span))
            }
        }
        ExprKind::Unary { op, expr } => {
            Ok(Expr::new(ExprKind::Unary { op, expr: Box::new(resolve_constant_references(*expr, constants, visiting)?) }, span))
        }
        ExprKind::Binary { op, left, right } => Ok(Expr::new(
            ExprKind::Binary {
                op,
                left: Box::new(resolve_constant_references(*left, constants, visiting)?),
                right: Box::new(resolve_constant_references(*right, constants, visiting)?),
            },
            span,
        )),
        ExprKind::Append { source, args, span: append_span } => Ok(Expr::new(
            ExprKind::Append {
                source: Box::new(resolve_constant_references(*source, constants, visiting)?),
                args: args
                    .into_iter()
                    .map(|arg| resolve_constant_references(arg, constants, visiting))
                    .collect::<Result<Vec<_>, _>>()?,
                span: append_span,
            },
            span,
        )),
        ExprKind::IfElse { condition, then_expr, else_expr } => Ok(Expr::new(
            ExprKind::IfElse {
                condition: Box::new(resolve_constant_references(*condition, constants, visiting)?),
                then_expr: Box::new(resolve_constant_references(*then_expr, constants, visiting)?),
                else_expr: Box::new(resolve_constant_references(*else_expr, constants, visiting)?),
            },
            span,
        )),
        ExprKind::Array(values) => {
            let mut resolved = Vec::with_capacity(values.len());
            for value in values {
                resolved.push(resolve_constant_references(value, constants, visiting)?);
            }
            Ok(Expr::new(ExprKind::Array(resolved), span))
        }
        ExprKind::StructLiteral { name, fields, name_span } => {
            let mut resolved_fields = Vec::with_capacity(fields.len());
            for field in fields {
                resolved_fields.push(StateFieldExpr {
                    name: field.name,
                    expr: resolve_constant_references(field.expr, constants, visiting)?,
                    span: field.span,
                    name_span: field.name_span,
                });
            }
            Ok(Expr::new(ExprKind::StructLiteral { name, fields: resolved_fields, name_span }, span))
        }
        ExprKind::FieldAccess { source, field, field_span } => Ok(Expr::new(
            ExprKind::FieldAccess { source: Box::new(resolve_constant_references(*source, constants, visiting)?), field, field_span },
            span,
        )),
        ExprKind::Call { name, args, name_span } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_constant_references(arg, constants, visiting)?);
            }
            Ok(Expr::new(ExprKind::Call { name, args: resolved, name_span }, span))
        }
        ExprKind::New { name, args, name_span } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in args {
                resolved.push(resolve_constant_references(arg, constants, visiting)?);
            }
            Ok(Expr::new(ExprKind::New { name, args: resolved, name_span }, span))
        }
        ExprKind::Split { source, index, part, span: split_span } => Ok(Expr::new(
            ExprKind::Split {
                source: Box::new(resolve_constant_references(*source, constants, visiting)?),
                index: Box::new(resolve_constant_references(*index, constants, visiting)?),
                part,
                span: split_span,
            },
            span,
        )),
        ExprKind::ArrayIndex { source, index } => Ok(Expr::new(
            ExprKind::ArrayIndex {
                source: Box::new(resolve_constant_references(*source, constants, visiting)?),
                index: Box::new(resolve_constant_references(*index, constants, visiting)?),
            },
            span,
        )),
        ExprKind::Introspection { kind, index, field_span } => Ok(Expr::new(
            ExprKind::Introspection { kind, index: Box::new(resolve_constant_references(*index, constants, visiting)?), field_span },
            span,
        )),
        ExprKind::UnarySuffix { source, kind, span: suffix_span } => Ok(Expr::new(
            ExprKind::UnarySuffix {
                source: Box::new(resolve_constant_references(*source, constants, visiting)?),
                kind,
                span: suffix_span,
            },
            span,
        )),
        ExprKind::Slice { source, start, end, span: slice_span } => Ok(Expr::new(
            ExprKind::Slice {
                source: Box::new(resolve_constant_references(*source, constants, visiting)?),
                start: Box::new(resolve_constant_references(*start, constants, visiting)?),
                end: Box::new(resolve_constant_references(*end, constants, visiting)?),
                span: slice_span,
            },
            span,
        )),
        other => Ok(Expr::new(other, span)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_const_int_rejects_checked_arithmetic_overflow() {
        let constants = HashMap::new();
        let cases = [
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Add, left: Box::new(Expr::int(i64::MAX)), right: Box::new(Expr::int(1)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} + 1", i64::MAX),
            ),
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Sub, left: Box::new(Expr::int(-i64::MAX)), right: Box::new(Expr::int(2)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} - 2", -i64::MAX),
            ),
            (
                Expr::new(
                    ExprKind::Binary {
                        op: BinaryOp::Mul,
                        left: Box::new(Expr::int(3_037_000_500)),
                        right: Box::new(Expr::int(3_037_000_500)),
                    },
                    Default::default(),
                ),
                "constant integer overflow: 3037000500 * 3037000500".to_string(),
            ),
            (
                Expr::new(ExprKind::Unary { op: UnaryOp::Neg, expr: Box::new(Expr::int(i64::MIN)) }, Default::default()),
                format!("constant integer overflow: -({})", i64::MIN),
            ),
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Div, left: Box::new(Expr::int(i64::MIN)), right: Box::new(Expr::int(-1)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} / -1", i64::MIN),
            ),
            (
                Expr::new(
                    ExprKind::Binary { op: BinaryOp::Mod, left: Box::new(Expr::int(i64::MIN)), right: Box::new(Expr::int(-1)) },
                    Default::default(),
                ),
                format!("constant integer overflow: {} % -1", i64::MIN),
            ),
        ];

        for (expr, expected) in cases {
            let err = eval_const_int(&expr, &constants).expect_err("overflow should be rejected");
            assert!(err.to_string().contains(&expected), "unexpected error: {err}");
        }
    }
}
