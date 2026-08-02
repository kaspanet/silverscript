use std::collections::HashMap;

use super::compile::encoded_state_len_for_layout_field_types;
use super::structs::{flatten_type_leaves, resolve_struct_access, struct_name};
use super::*;
use crate::ast::{ArrayDim, ContractAst, Expr, ExprKind, FunctionAst, STATE_TYPE_NAME, Statement, TypeBase, TypeRef};
use crate::span;

pub(super) const VALIDATE_OUTPUT_STATE_INNER: &str = "__validateOutputStateInner";
pub(super) const VALIDATE_OUTPUT_STATE_WITH_TEMPLATE_INNER: &str = "__validateOutputStateWithTemplateInner";

#[derive(Clone, Default)]
struct ValidationScope {
    vars: HashMap<String, TypeRef>,
    temp_index: usize,
}

pub(super) fn lower_validate_output_state<'i>(
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let functions = contract
        .functions
        .iter()
        .map(|function| lower_function(function, contract, structs, constants))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ContractAst { functions, ..contract.clone() })
}

fn lower_function<'i>(
    function: &FunctionAst<'i>,
    contract: &ContractAst<'i>,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<FunctionAst<'i>, CompilerError> {
    let mut scope = ValidationScope::default();
    for param in &contract.params {
        scope.vars.insert(param.name.clone(), param.type_ref.clone());
    }
    for constant in &contract.constants {
        scope.vars.insert(constant.name.clone(), constant.type_ref.clone());
    }
    for field in &contract.fields {
        scope.vars.insert(field.name.clone(), field.type_ref.clone());
    }
    for param in &function.params {
        scope.vars.insert(param.name.clone(), param.type_ref.clone());
    }
    Ok(FunctionAst { body: lower_statements(&function.body, &mut scope, structs, constants)?, ..function.clone() })
}

fn lower_statements<'i>(
    statements: &[Statement<'i>],
    scope: &mut ValidationScope,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    let mut lowered = Vec::new();
    for statement in statements {
        lowered.extend(lower_statement(statement, scope, structs, constants)?);
    }
    Ok(lowered)
}

fn lower_statement<'i>(
    statement: &Statement<'i>,
    scope: &mut ValidationScope,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<Vec<Statement<'i>>, CompilerError> {
    match statement {
        Statement::FunctionCall { name, args, span, name_span } if name == "validateOutputState" => {
            let Ok([output_idx, state_expr]): Result<&[Expr<'i>; 2], _> = args.as_slice().try_into() else {
                return Err(CompilerError::Unsupported("validateOutputState(output_idx, new_state) expects 2 arguments".to_string()));
            };

            let mut lowered = Vec::new();
            let state_expr = if matches!(state_expr.kind, ExprKind::Identifier(_)) {
                state_expr.clone()
            } else {
                let temp_name = unique_state_temp_name(scope);
                let state_type = state_type();
                scope.vars.insert(temp_name.clone(), state_type.clone());
                lowered.push(Statement::VariableDefinition {
                    type_ref: state_type,
                    modifiers: Vec::new(),
                    name: temp_name.clone(),
                    expr: Some(state_expr.clone()),
                    span: *span,
                    type_span: span::Span::default(),
                    modifier_spans: Vec::new(),
                    name_span: span::Span::default(),
                });
                Expr::identifier(temp_name)
            };

            let mut lowered_args = vec![output_idx.clone()];
            lowered_args.extend(flatten_state_expr(&state_expr, scope, structs)?);
            lowered.push(Statement::FunctionCall {
                name: VALIDATE_OUTPUT_STATE_INNER.to_string(),
                args: lowered_args,
                span: *span,
                name_span: *name_span,
            });
            Ok(lowered)
        }
        Statement::FunctionCall { name, args, span, name_span } if name == "validateOutputStateWithTemplate" => {
            let Ok([output_idx, state_expr, template_prefix, template_suffix, expected_template_hash]): Result<&[Expr<'i>; 5], _> =
                args.as_slice().try_into()
            else {
                return Err(CompilerError::Unsupported(
                    "validateOutputStateWithTemplate(output_idx, new_state, template_prefix, template_suffix, expected_template_hash) expects 5 arguments"
                        .to_string(),
                ));
            };

            let mut lowered = Vec::new();
            let state_type = infer_template_state_type(state_expr, scope, structs)?;
            let state_expr = if matches!(state_expr.kind, ExprKind::Identifier(_)) {
                state_expr.clone()
            } else {
                let temp_name = unique_state_temp_name(scope);
                scope.vars.insert(temp_name.clone(), state_type.clone());
                lowered.push(Statement::VariableDefinition {
                    type_ref: state_type.clone(),
                    modifiers: Vec::new(),
                    name: temp_name.clone(),
                    expr: Some(state_expr.clone()),
                    span: *span,
                    type_span: span::Span::default(),
                    modifier_spans: Vec::new(),
                    name_span: span::Span::default(),
                });
                Expr::identifier(temp_name)
            };

            let mut lowered_args = vec![output_idx.clone()];
            lowered_args.extend(flatten_struct_expr(&state_expr, &state_type, scope, structs)?);
            lowered_args.extend([template_prefix.clone(), template_suffix.clone(), expected_template_hash.clone()]);
            lowered.push(Statement::FunctionCall {
                name: VALIDATE_OUTPUT_STATE_WITH_TEMPLATE_INNER.to_string(),
                args: lowered_args,
                span: *span,
                name_span: *name_span,
            });
            Ok(lowered)
        }
        Statement::FunctionCall { name, args, span, name_span } if name == "validateOutputStateWithInputTemplate" => {
            let Ok([output_idx, state_expr, template_input_idx, template_prefix_len, template_suffix_len, expected_template_hash]): Result<
                &[Expr<'i>; 6],
                _,
            > = args.as_slice().try_into()
            else {
                return Err(CompilerError::Unsupported(
                    "validateOutputStateWithInputTemplate(output_idx, new_state, template_input_idx, template_prefix_len, template_suffix_len, expected_template_hash) expects 6 arguments"
                        .to_string(),
                ));
            };

            let state_type = infer_template_state_type(state_expr, scope, structs)?;
            let (template_prefix, template_suffix) =
                input_template_parts(template_input_idx, template_prefix_len, template_suffix_len, &state_type, structs, constants)?;
            let (prefix_bindings, prefix_ref) = bind_template_part(scope, "prefix", template_prefix, *span);
            let (suffix_bindings, suffix_ref) = bind_template_part(scope, "suffix", template_suffix, *span);
            let template_call = Statement::FunctionCall {
                name: "validateOutputStateWithTemplate".to_string(),
                args: vec![output_idx.clone(), state_expr.clone(), prefix_ref, suffix_ref, expected_template_hash.clone()],
                span: *span,
                name_span: *name_span,
            };
            let mut lowered = prefix_bindings;
            lowered.extend(suffix_bindings);
            lowered.extend(lower_statement(&template_call, scope, structs, constants)?);
            Ok(lowered)
        }
        Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
            let lowered = Statement::VariableDefinition {
                type_ref: type_ref.clone(),
                modifiers: modifiers.clone(),
                name: name.clone(),
                expr: expr.clone(),
                span: *span,
                type_span: *type_span,
                modifier_spans: modifier_spans.clone(),
                name_span: *name_span,
            };
            scope.vars.insert(name.clone(), type_ref.clone());
            Ok(vec![lowered])
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
            scope.vars.insert(left_name.clone(), left_type_ref.clone());
            scope.vars.insert(right_name.clone(), right_type_ref.clone());
            Ok(vec![Statement::TupleAssignment {
                left_type_ref: left_type_ref.clone(),
                left_name: left_name.clone(),
                right_type_ref: right_type_ref.clone(),
                right_name: right_name.clone(),
                expr: expr.clone(),
                span: *span,
                left_type_span: *left_type_span,
                left_name_span: *left_name_span,
                right_type_span: *right_type_span,
                right_name_span: *right_name_span,
            }])
        }
        Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
            for binding in bindings {
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
            }
            Ok(vec![Statement::FunctionCallAssign {
                bindings: bindings.clone(),
                name: name.clone(),
                args: args.clone(),
                span: *span,
                name_span: *name_span,
            }])
        }
        Statement::StateFunctionCallAssign { bindings, name, args, span, name_span } => {
            for binding in bindings {
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
            }
            Ok(vec![Statement::StateFunctionCallAssign {
                bindings: bindings.clone(),
                name: name.clone(),
                args: args.clone(),
                span: *span,
                name_span: *name_span,
            }])
        }
        Statement::StructDestructure { bindings, expr, span } => {
            for binding in bindings {
                scope.vars.insert(binding.name.clone(), binding.type_ref.clone());
            }
            Ok(vec![Statement::StructDestructure { bindings: bindings.clone(), expr: expr.clone(), span: *span }])
        }
        Statement::Block { body, span } => {
            let mut block_scope = scope.clone();
            Ok(vec![Statement::Block { body: lower_statements(body, &mut block_scope, structs, constants)?, span: *span }])
        }
        Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
            let mut then_scope = scope.clone();
            let lowered_then = lower_statements(then_branch, &mut then_scope, structs, constants)?;
            let lowered_else = if let Some(else_branch) = else_branch {
                let mut else_scope = scope.clone();
                Some(lower_statements(else_branch, &mut else_scope, structs, constants)?)
            } else {
                None
            };
            Ok(vec![Statement::If {
                condition: condition.clone(),
                then_branch: lowered_then,
                else_branch: lowered_else,
                span: *span,
                then_span: *then_span,
                else_span: *else_span,
            }])
        }
        Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
            let mut body_scope = scope.clone();
            body_scope.vars.insert(ident.clone(), TypeRef { base: TypeBase::Int, array_dims: Vec::new() });
            Ok(vec![Statement::For {
                ident: ident.clone(),
                start: start.clone(),
                end: end.clone(),
                max_iterations: max_iterations.clone(),
                body: lower_statements(body, &mut body_scope, structs, constants)?,
                span: *span,
                ident_span: *ident_span,
                body_span: *body_span,
            }])
        }
        _ => Ok(vec![statement.clone()]),
    }
}

fn input_template_parts<'i>(
    input_idx: &Expr<'i>,
    template_prefix_len: &Expr<'i>,
    template_suffix_len: &Expr<'i>,
    state_type: &TypeRef,
    structs: &StructRegistry,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<(Expr<'i>, Expr<'i>), CompilerError> {
    let layout_field_types = flatten_type_leaves(state_type, structs)?.into_iter().map(|(_, type_ref)| type_ref).collect::<Vec<_>>();
    let state_len = encoded_state_len_for_layout_field_types(&layout_field_types, constants).map_err(|_| {
        CompilerError::Unsupported("validateOutputStateWithInputTemplate requires a fixed-size state layout".to_string())
    })?;
    Ok(input_template_parts_exprs(input_idx, template_prefix_len, template_suffix_len, state_len))
}

fn input_template_parts_exprs<'i>(
    input_idx: &Expr<'i>,
    template_prefix_len: &Expr<'i>,
    template_suffix_len: &Expr<'i>,
    state_len: usize,
) -> (Expr<'i>, Expr<'i>) {
    let script_size = binary_expr(
        BinaryOp::Add,
        binary_expr(BinaryOp::Add, template_prefix_len.clone(), Expr::int(state_len as i64)),
        template_suffix_len.clone(),
    );
    let script_base = input_sigscript_base_expr(input_idx, script_size.clone());
    let prefix_end = binary_expr(BinaryOp::Add, script_base.clone(), template_prefix_len.clone());
    let suffix_start = binary_expr(BinaryOp::Add, prefix_end.clone(), Expr::int(state_len as i64));
    let suffix_end = binary_expr(BinaryOp::Add, suffix_start.clone(), template_suffix_len.clone());
    (input_sigscript_substr_expr(input_idx, script_base, prefix_end), input_sigscript_substr_expr(input_idx, suffix_start, suffix_end))
}

fn input_sigscript_base_expr<'i>(input_idx: &Expr<'i>, script_size_expr: Expr<'i>) -> Expr<'i> {
    binary_expr(BinaryOp::Sub, Expr::call("OpTxInputScriptSigLen", vec![input_idx.clone()]), script_size_expr)
}

fn input_sigscript_substr_expr<'i>(input_idx: &Expr<'i>, start: Expr<'i>, end: Expr<'i>) -> Expr<'i> {
    Expr::call("OpTxInputScriptSigSubstr", vec![input_idx.clone(), start, end])
}

fn bind_template_part<'i>(
    scope: &mut ValidationScope,
    part: &str,
    expr: Expr<'i>,
    statement_span: span::Span<'i>,
) -> (Vec<Statement<'i>>, Expr<'i>) {
    let name = loop {
        let name = format!("__input_template_{part}_{}", scope.temp_index);
        scope.temp_index += 1;
        if !scope.vars.contains_key(&name) {
            break name;
        }
    };
    let type_ref = TypeRef { base: TypeBase::Byte, array_dims: vec![ArrayDim::Dynamic] };
    scope.vars.insert(name.clone(), type_ref.clone());
    // Assignment keeps the slice stack-bound; immutable single-use locals are
    // inlined before the inner validation expands its repeated references.
    // TODO: Replace this workaround by lowering validateOutputStateWithTemplate
    // before locals.rs, or by binding its template parts internally.
    let binding = Statement::VariableDefinition {
        type_ref: type_ref.clone(),
        modifiers: Vec::new(),
        name: name.clone(),
        expr: None,
        span: statement_span,
        type_span: span::Span::default(),
        modifier_spans: Vec::new(),
        name_span: span::Span::default(),
    };
    let assignment = Statement::Assign { name: name.clone(), expr, span: statement_span, name_span: span::Span::default() };
    (vec![binding, assignment], Expr::identifier(name))
}

fn flatten_state_expr<'i>(expr: &Expr<'i>, scope: &ValidationScope, structs: &StructRegistry) -> Result<Vec<Expr<'i>>, CompilerError> {
    let state_type = state_type();
    flatten_struct_expr(expr, &state_type, scope, structs)
}

fn state_type() -> TypeRef {
    TypeRef { base: TypeBase::Custom(STATE_TYPE_NAME.to_string()), array_dims: Vec::new() }
}

fn unique_state_temp_name(scope: &mut ValidationScope) -> String {
    loop {
        let name = format!("__validate_output_state_{}", scope.temp_index);
        scope.temp_index += 1;
        if !scope.vars.contains_key(&name) {
            return name;
        }
    }
}

fn infer_template_state_type(expr: &Expr<'_>, scope: &ValidationScope, structs: &StructRegistry) -> Result<TypeRef, CompilerError> {
    let struct_scope = super::structs::LoweringScope { vars: scope.vars.clone() };
    match &expr.kind {
        ExprKind::Identifier(_) | ExprKind::FieldAccess { .. } => {
            let (_, _, type_ref) = resolve_struct_access(expr, &struct_scope, structs)?;
            Ok(type_ref)
        }
        ExprKind::ArrayIndex { source, .. } => {
            let ExprKind::Identifier(name) = &source.kind else {
                return Err(CompilerError::Unsupported("validateOutputStateWithTemplate requires a struct value".to_string()));
            };
            scope
                .vars
                .get(name)
                .cloned()
                .ok_or_else(|| CompilerError::UndefinedIdentifier(name.clone()))?
                .array_element_type()
                .ok_or_else(|| CompilerError::Unsupported("validateOutputStateWithTemplate requires a struct value".to_string()))
        }
        ExprKind::StructLiteral(_) => Err(CompilerError::Unsupported(
            "validateOutputStateWithTemplate does not support inline state objects; use a struct variable instead".to_string(),
        )),
        _ => Err(CompilerError::Unsupported("validateOutputStateWithTemplate requires a struct value".to_string())),
    }
}

fn flatten_struct_expr<'i>(
    expr: &Expr<'i>,
    expected_type: &TypeRef,
    scope: &ValidationScope,
    structs: &StructRegistry,
) -> Result<Vec<Expr<'i>>, CompilerError> {
    let expected_struct_name = struct_name(expected_type, structs)
        .ok_or_else(|| CompilerError::Unsupported(format!("expected struct type '{}'", expected_type.type_name())))?;

    if !matches!(&expr.kind, ExprKind::Identifier(_)) {
        return Err(CompilerError::Unsupported("flatten_struct_expr expects an identifier".into()));
    }

    let struct_scope = super::structs::LoweringScope { vars: scope.vars.clone() };
    let (base, path, actual_type) = resolve_struct_access(expr, &struct_scope, structs)?;
    let actual_struct_name =
        struct_name(&actual_type, structs).ok_or_else(|| CompilerError::Unsupported("expression is not a struct".to_string()))?;
    if actual_struct_name != expected_struct_name {
        return Err(CompilerError::Unsupported(format!(
            "struct expression expects {}, got {}",
            expected_struct_name,
            actual_type.type_name()
        )));
    }

    let leaves = flatten_type_leaves(&actual_type, structs)?;
    Ok(leaves
        .into_iter()
        .map(|(leaf_path, _)| {
            let mut full_path = path.clone();
            full_path.extend(leaf_path);
            field_access_chain(&base, &full_path)
        })
        .collect())
}

fn field_access_chain<'i>(base: &str, path: &[String]) -> Expr<'i> {
    let mut expr = Expr::identifier(base);
    for field in path {
        expr = Expr::new(
            ExprKind::FieldAccess { source: Box::new(expr), field: field.clone(), field_span: span::Span::default() },
            span::Span::default(),
        );
    }
    expr
}
