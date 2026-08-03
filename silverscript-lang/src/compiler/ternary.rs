use std::collections::HashMap;

use super::*;

const TERNARY_RESULT_PREFIX: &str = "__ternary";

pub(super) fn lower_ternaries<'i>(
    contract: &ContractAst<'i>,
    constants: &HashMap<String, Expr<'i>>,
) -> Result<ContractAst<'i>, CompilerError> {
    let structs = build_struct_registry(contract)?;
    let functions = contract.functions.iter().map(|function| (function.name.clone(), function)).collect::<HashMap<_, _>>();
    let mut lowerer =
        TernaryLowerer { structs: &structs, constants, functions: &functions, contract_fields: &contract.fields, fresh_counter: 0 };

    let functions =
        contract.functions.iter().map(|function| lowerer.lower_function(contract, function)).collect::<Result<Vec<_>, _>>()?;

    Ok(ContractAst { functions, ..contract.clone() })
}

struct TernaryLowerer<'a, 'i> {
    structs: &'a StructRegistry,
    constants: &'a HashMap<String, Expr<'i>>,
    functions: &'a HashMap<String, &'a FunctionAst<'i>>,
    contract_fields: &'a [ContractFieldAst<'i>],
    fresh_counter: usize,
}

impl<'a, 'i> TernaryLowerer<'a, 'i> {
    fn lower_function(&mut self, contract: &ContractAst<'i>, function: &FunctionAst<'i>) -> Result<FunctionAst<'i>, CompilerError> {
        let mut types = TypeMap::new();
        for param in &contract.params {
            types.insert(param.name.clone(), param.type_ref.clone());
        }
        for field in &contract.fields {
            types.insert(field.name.clone(), field.type_ref.clone());
        }
        for constant in &contract.constants {
            types.insert(constant.name.clone(), constant.type_ref.clone());
        }
        for param in &function.params {
            types.insert(param.name.clone(), param.type_ref.clone());
        }

        let body = self.lower_block(&function.body, &mut types, &function.return_types)?;
        Ok(FunctionAst { body, ..function.clone() })
    }

    fn lower_block(
        &mut self,
        statements: &[Statement<'i>],
        types: &mut TypeMap,
        return_types: &[TypeRef],
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let mut lowered = Vec::new();
        for statement in statements {
            lowered.extend(self.lower_statement(statement, types, return_types)?);
        }
        Ok(lowered)
    }

    fn lower_statement(
        &mut self,
        statement: &Statement<'i>,
        types: &mut TypeMap,
        return_types: &[TypeRef],
    ) -> Result<Vec<Statement<'i>>, CompilerError> {
        let mut lowered = Vec::new();
        match statement {
            Statement::VariableDefinition { type_ref, modifiers, name, expr, span, type_span, modifier_spans, name_span } => {
                let expr = if let Some(expr) = expr {
                    let (prelude, expr) = self.lower_expr(expr, Some(type_ref), types)?;
                    lowered.extend(prelude);
                    Some(expr)
                } else {
                    None
                };
                types.insert(name.clone(), type_ref.clone());
                lowered.push(Statement::VariableDefinition {
                    type_ref: type_ref.clone(),
                    modifiers: modifiers.clone(),
                    name: name.clone(),
                    expr,
                    span: *span,
                    type_span: *type_span,
                    modifier_spans: modifier_spans.clone(),
                    name_span: *name_span,
                });
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
                let (prelude, expr) = self.lower_expr(expr, None, types)?;
                lowered.extend(prelude);
                types.insert(left_name.clone(), left_type_ref.clone());
                types.insert(right_name.clone(), right_type_ref.clone());
                lowered.push(Statement::TupleAssignment {
                    left_type_ref: left_type_ref.clone(),
                    left_name: left_name.clone(),
                    right_type_ref: right_type_ref.clone(),
                    right_name: right_name.clone(),
                    expr,
                    span: *span,
                    left_type_span: *left_type_span,
                    left_name_span: *left_name_span,
                    right_type_span: *right_type_span,
                    right_name_span: *right_name_span,
                });
            }
            Statement::FunctionCallAssign { bindings, name, args, span, name_span } => {
                let (prelude, args) = self.lower_exprs(args, types)?;
                lowered.extend(prelude);
                for binding in bindings {
                    types.insert(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::FunctionCallAssign {
                    bindings: bindings.clone(),
                    name: name.clone(),
                    args,
                    span: *span,
                    name_span: *name_span,
                });
            }
            Statement::StateFunctionCallAssign { bindings, name, args, span, name_span, target_struct } => {
                let (prelude, args) = self.lower_exprs(args, types)?;
                lowered.extend(prelude);
                for binding in bindings {
                    types.insert(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::StateFunctionCallAssign {
                    bindings: bindings.clone(),
                    name: name.clone(),
                    args,
                    span: *span,
                    name_span: *name_span,
                    target_struct: target_struct.clone(),
                });
            }
            Statement::StructDestructure { struct_name, bindings, expr, span } => {
                let (prelude, expr) = self.lower_expr(expr, None, types)?;
                lowered.extend(prelude);
                for binding in bindings {
                    types.insert(binding.name.clone(), binding.type_ref.clone());
                }
                lowered.push(Statement::StructDestructure {
                    struct_name: struct_name.clone(),
                    bindings: bindings.clone(),
                    expr,
                    span: *span,
                });
            }
            Statement::FunctionCall { name, args, span, name_span } => {
                let (prelude, args) = self.lower_exprs(args, types)?;
                lowered.extend(prelude);
                lowered.push(Statement::FunctionCall { name: name.clone(), args, span: *span, name_span: *name_span });
            }
            Statement::Return { exprs, span } => {
                let mut lowered_exprs = Vec::with_capacity(exprs.len());
                for (index, expr) in exprs.iter().enumerate() {
                    let (prelude, expr) = self.lower_expr(expr, return_types.get(index), types)?;
                    lowered.extend(prelude);
                    lowered_exprs.push(expr);
                }
                lowered.push(Statement::Return { exprs: lowered_exprs, span: *span });
            }
            Statement::Require { expr, message, span, message_span } => {
                let expected = TypeRef { base: TypeBase::Bool, array_dims: Vec::new() };
                let (prelude, expr) = self.lower_expr(expr, Some(&expected), types)?;
                lowered.extend(prelude);
                lowered.push(Statement::Require { expr, message: message.clone(), span: *span, message_span: *message_span });
            }
            Statement::TimeOp { tx_var, expr, message, span, tx_var_span, message_span } => {
                let expected = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
                let (prelude, expr) = self.lower_expr(expr, Some(&expected), types)?;
                lowered.extend(prelude);
                lowered.push(Statement::TimeOp {
                    tx_var: *tx_var,
                    expr,
                    message: message.clone(),
                    span: *span,
                    tx_var_span: *tx_var_span,
                    message_span: *message_span,
                });
            }
            Statement::Console { args, span } => {
                let (prelude, args) = self.lower_exprs(args, types)?;
                lowered.extend(prelude);
                lowered.push(Statement::Console { args, span: *span });
            }
            Statement::Assign { name, expr, span, name_span } => {
                let expected = types.get(name).cloned();
                let (prelude, expr) = self.lower_expr(expr, expected.as_ref(), types)?;
                lowered.extend(prelude);
                lowered.push(Statement::Assign { name: name.clone(), expr, span: *span, name_span: *name_span });
            }
            Statement::Block { body, span } => {
                let mut block_types = types.clone();
                let body = self.lower_block(body, &mut block_types, return_types)?;
                lowered.push(Statement::Block { body, span: *span });
            }
            Statement::If { condition, then_branch, else_branch, span, then_span, else_span } => {
                let expected = TypeRef { base: TypeBase::Bool, array_dims: Vec::new() };
                let (prelude, condition) = self.lower_expr(condition, Some(&expected), types)?;
                lowered.extend(prelude);
                let mut then_types = types.clone();
                let then_branch = self.lower_block(then_branch, &mut then_types, return_types)?;
                let else_branch = else_branch
                    .as_ref()
                    .map(|branch| {
                        let mut else_types = types.clone();
                        self.lower_block(branch, &mut else_types, return_types)
                    })
                    .transpose()?;
                lowered.push(Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    span: *span,
                    then_span: *then_span,
                    else_span: *else_span,
                });
            }
            Statement::For { ident, start, end, max_iterations, body, span, ident_span, body_span } => {
                let expected = TypeRef { base: TypeBase::Int, array_dims: Vec::new() };
                let (prelude, start) = self.lower_expr(start, Some(&expected), types)?;
                lowered.extend(prelude);
                let (prelude, end) = self.lower_expr(end, Some(&expected), types)?;
                lowered.extend(prelude);
                let (prelude, max_iterations) = self.lower_expr(max_iterations, Some(&expected), types)?;
                lowered.extend(prelude);
                let mut body_types = types.clone();
                body_types.insert(ident.clone(), expected);
                let body = self.lower_block(body, &mut body_types, return_types)?;
                lowered.push(Statement::For {
                    ident: ident.clone(),
                    start,
                    end,
                    max_iterations,
                    body,
                    span: *span,
                    ident_span: *ident_span,
                    body_span: *body_span,
                });
            }
        }
        Ok(lowered)
    }

    fn lower_exprs(&mut self, exprs: &[Expr<'i>], types: &mut TypeMap) -> Result<(Vec<Statement<'i>>, Vec<Expr<'i>>), CompilerError> {
        let mut prelude = Vec::new();
        let mut lowered_exprs = Vec::with_capacity(exprs.len());
        for expr in exprs {
            let (more_prelude, expr) = self.lower_expr(expr, None, types)?;
            prelude.extend(more_prelude);
            lowered_exprs.push(expr);
        }
        Ok((prelude, lowered_exprs))
    }

    fn lower_expr(
        &mut self,
        expr: &Expr<'i>,
        expected: Option<&TypeRef>,
        types: &mut TypeMap,
    ) -> Result<(Vec<Statement<'i>>, Expr<'i>), CompilerError> {
        let span = expr.span;
        match &expr.kind {
            ExprKind::Ternary { condition, then_expr, else_expr } => {
                let result_type = self.check_expr(expr, expected, types)?;
                let bool_type = TypeRef { base: TypeBase::Bool, array_dims: Vec::new() };
                let (mut prelude, condition) = self.lower_expr(condition, Some(&bool_type), types)?;
                let result_name = self.fresh_result_name();
                let default = self.default_expr(&result_type, span)?;
                types.insert(result_name.clone(), result_type.clone());

                prelude.push(Statement::VariableDefinition {
                    type_ref: result_type.clone(),
                    modifiers: Vec::new(),
                    name: result_name.clone(),
                    expr: Some(default),
                    span,
                    type_span: span,
                    modifier_spans: Vec::new(),
                    name_span: span,
                });

                let mut then_types = types.clone();
                let (mut then_branch, then_expr) = self.lower_expr(then_expr, Some(&result_type), &mut then_types)?;
                then_branch.push(Statement::Assign { name: result_name.clone(), expr: then_expr, span, name_span: span });

                let mut else_types = types.clone();
                let (mut else_branch, else_expr) = self.lower_expr(else_expr, Some(&result_type), &mut else_types)?;
                else_branch.push(Statement::Assign { name: result_name.clone(), expr: else_expr, span, name_span: span });

                prelude.push(Statement::If {
                    condition,
                    then_branch,
                    else_branch: Some(else_branch),
                    span,
                    then_span: span,
                    else_span: Some(span),
                });

                Ok((prelude, Expr::new(ExprKind::Identifier(result_name), span)))
            }
            ExprKind::Array { type_ref, values } => {
                let element_type = expected.or(Some(type_ref)).and_then(TypeRef::array_element_type);
                let mut prelude = Vec::new();
                let mut lowered_values = Vec::with_capacity(values.len());
                for value in values {
                    let (more_prelude, value) = self.lower_expr(value, element_type.as_ref(), types)?;
                    prelude.extend(more_prelude);
                    lowered_values.push(value);
                }
                Ok((prelude, Expr::new(ExprKind::Array { type_ref: type_ref.clone(), values: lowered_values }, span)))
            }
            ExprKind::Call { name, args, name_span } => {
                let (prelude, args) = self.lower_exprs(args, types)?;
                Ok((prelude, Expr::new(ExprKind::Call { name: name.clone(), args, name_span: *name_span }, span)))
            }
            ExprKind::New { name, args, name_span } => {
                let (prelude, args) = self.lower_exprs(args, types)?;
                Ok((prelude, Expr::new(ExprKind::New { name: name.clone(), args, name_span: *name_span }, span)))
            }
            ExprKind::Unary { op, expr } => {
                let (prelude, expr) = self.lower_expr(expr, None, types)?;
                Ok((prelude, Expr::new(ExprKind::Unary { op: *op, expr: Box::new(expr) }, span)))
            }
            ExprKind::Binary { op, left, right } => {
                let (mut prelude, left) = self.lower_expr(left, None, types)?;
                let (more_prelude, right) = self.lower_expr(right, None, types)?;
                prelude.extend(more_prelude);
                Ok((prelude, Expr::new(ExprKind::Binary { op: *op, left: Box::new(left), right: Box::new(right) }, span)))
            }
            ExprKind::Append { source, args, span: append_span } => {
                let (mut prelude, source) = self.lower_expr(source, None, types)?;
                let (more_prelude, args) = self.lower_exprs(args, types)?;
                prelude.extend(more_prelude);
                Ok((prelude, Expr::new(ExprKind::Append { source: Box::new(source), args, span: *append_span }, span)))
            }
            ExprKind::Split { source, index, part, span: split_span } => {
                let (mut prelude, source) = self.lower_expr(source, None, types)?;
                let (more_prelude, index) = self.lower_expr(index, None, types)?;
                prelude.extend(more_prelude);
                Ok((
                    prelude,
                    Expr::new(
                        ExprKind::Split { source: Box::new(source), index: Box::new(index), part: *part, span: *split_span },
                        span,
                    ),
                ))
            }
            ExprKind::UnarySuffix { source, kind, span: suffix_span } => {
                let (prelude, source) = self.lower_expr(source, None, types)?;
                Ok((prelude, Expr::new(ExprKind::UnarySuffix { source: Box::new(source), kind: *kind, span: *suffix_span }, span)))
            }
            ExprKind::ArrayIndex { source, index } => {
                let (mut prelude, source) = self.lower_expr(source, None, types)?;
                let (more_prelude, index) = self.lower_expr(index, None, types)?;
                prelude.extend(more_prelude);
                Ok((prelude, Expr::new(ExprKind::ArrayIndex { source: Box::new(source), index: Box::new(index) }, span)))
            }
            ExprKind::Slice { source, start, end, span: slice_span } => {
                let (mut prelude, source) = self.lower_expr(source, None, types)?;
                let (more_prelude, start) = self.lower_expr(start, None, types)?;
                prelude.extend(more_prelude);
                let (more_prelude, end) = self.lower_expr(end, None, types)?;
                prelude.extend(more_prelude);
                Ok((
                    prelude,
                    Expr::new(
                        ExprKind::Slice { source: Box::new(source), start: Box::new(start), end: Box::new(end), span: *slice_span },
                        span,
                    ),
                ))
            }
            ExprKind::Introspection { kind, index, field_span } => {
                let (prelude, index) = self.lower_expr(index, None, types)?;
                Ok((
                    prelude,
                    Expr::new(ExprKind::Introspection { kind: *kind, index: Box::new(index), field_span: *field_span }, span),
                ))
            }
            ExprKind::StructLiteral { name, fields, name_span } => {
                let struct_fields = expected
                    .and_then(|type_ref| struct_name(type_ref, self.structs))
                    .and_then(|name| self.structs.get(name))
                    .map(|item| item.fields.iter().map(|field| (field.name.as_str(), &field.type_ref)).collect::<HashMap<_, _>>());
                let mut prelude = Vec::new();
                let mut lowered_fields = Vec::with_capacity(fields.len());
                for field in fields {
                    let expected = struct_fields.as_ref().and_then(|fields| fields.get(field.name.as_str())).copied();
                    let (more_prelude, expr) = self.lower_expr(&field.expr, expected, types)?;
                    prelude.extend(more_prelude);
                    lowered_fields.push(StateFieldExpr { expr, ..field.clone() });
                }
                Ok((
                    prelude,
                    Expr::new(ExprKind::StructLiteral { name: name.clone(), fields: lowered_fields, name_span: *name_span }, span),
                ))
            }
            ExprKind::FieldAccess { source, field, field_span } => {
                let (prelude, source) = self.lower_expr(source, None, types)?;
                Ok((
                    prelude,
                    Expr::new(ExprKind::FieldAccess { source: Box::new(source), field: field.clone(), field_span: *field_span }, span),
                ))
            }
            ExprKind::Int(_)
            | ExprKind::Bool(_)
            | ExprKind::Byte(_)
            | ExprKind::String(_)
            | ExprKind::DateLiteral(_)
            | ExprKind::Identifier(_)
            | ExprKind::Nullary(_)
            | ExprKind::NumberWithUnit { .. } => Ok((Vec::new(), expr.clone())),
        }
    }

    fn check_expr(&self, expr: &Expr<'i>, expected: Option<&TypeRef>, types: &TypeMap) -> Result<TypeRef, CompilerError> {
        let ctx = type_check::TypeCheckContext {
            types,
            structs: self.structs,
            constants: self.constants,
            functions: self.functions,
            contract_fields: self.contract_fields,
        };
        type_check::check_expr(expr, expected, &ctx)
    }

    fn fresh_result_name(&mut self) -> String {
        let name = format!("{TERNARY_RESULT_PREFIX}_{}", self.fresh_counter);
        self.fresh_counter += 1;
        name
    }

    fn default_expr(&self, type_ref: &TypeRef, span: span::Span<'i>) -> Result<Expr<'i>, CompilerError> {
        if type_ref.is_array() {
            let element_type = type_ref
                .array_element_type()
                .ok_or_else(|| CompilerError::Unsupported("ternary result array element type is missing".to_string()))?;
            let len = match type_ref.array_size() {
                Some(ArrayDim::Dynamic) => 0,
                Some(ArrayDim::Fixed(_) | ArrayDim::Constant(_)) => array_type_size(type_ref, self.constants)
                    .ok_or_else(|| CompilerError::Unsupported(format!("cannot determine size of {}", type_ref.type_name())))?,
                Some(ArrayDim::Inferred) | None => {
                    return Err(CompilerError::Unsupported(format!("cannot create default {}", type_ref.type_name())));
                }
            };
            let values = (0..len).map(|_| self.default_expr(&element_type, span)).collect::<Result<Vec<_>, CompilerError>>()?;
            return Ok(Expr::new(ExprKind::Array { type_ref: type_ref.clone(), values }, span));
        }

        let kind = match &type_ref.base {
            TypeBase::Int => ExprKind::Int(0),
            TypeBase::Bool => ExprKind::Bool(false),
            TypeBase::String => ExprKind::String(String::new()),
            TypeBase::Byte => ExprKind::Byte(0),
            TypeBase::Pubkey | TypeBase::Sig | TypeBase::Datasig => {
                let len = type_ref
                    .base
                    .fixed_byte_sequence_len()
                    .ok_or_else(|| CompilerError::Unsupported(format!("cannot create default {}", type_ref.type_name())))?;
                ExprKind::Array { type_ref: type_ref.clone(), values: (0..len).map(|_| Expr::new(ExprKind::Byte(0), span)).collect() }
            }
            TypeBase::Custom(name) => {
                let item = self
                    .structs
                    .get(name)
                    .ok_or_else(|| CompilerError::Unsupported(format!("cannot create default for unknown type '{name}'")))?;
                let fields = item
                    .fields
                    .iter()
                    .map(|field| {
                        Ok(StateFieldExpr {
                            name: field.name.clone(),
                            expr: self.default_expr(&field.type_ref, span)?,
                            span,
                            name_span: span,
                        })
                    })
                    .collect::<Result<Vec<_>, CompilerError>>()?;
                ExprKind::StructLiteral { name: name.clone(), fields, name_span: span }
            }
            TypeBase::Tuple(_) => {
                return Err(CompilerError::Unsupported("ternary tuple results are not supported".to_string()));
            }
        };
        Ok(Expr::new(kind, span))
    }
}
