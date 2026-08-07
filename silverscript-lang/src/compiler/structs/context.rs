use super::*;

#[derive(Clone, Default)]
pub(crate) struct LoweringScope {
    pub(crate) vars: HashMap<String, TypeRef>,
}

impl LoweringScope {
    pub fn child(&self) -> Self {
        self.clone()
    }

    pub fn declare(&mut self, name: impl Into<String>, type_ref: TypeRef) {
        self.vars.insert(name.into(), type_ref);
    }

    pub fn type_of(&self, name: &str) -> Option<&TypeRef> {
        self.vars.get(name)
    }
}

pub(super) struct StructLowerer<'a, 'i> {
    pub structs: &'a StructRegistry,
    pub functions: &'a HashMap<String, FunctionAst<'i>>,
    pub contract_fields: &'a [ContractFieldAst<'i>],
    pub contract_constants: &'a HashMap<String, Expr<'i>>,
    pub contract_fields_end_offset: usize,
}

impl<'a, 'i> StructLowerer<'a, 'i> {
    pub fn new(
        structs: &'a StructRegistry,
        functions: &'a HashMap<String, FunctionAst<'i>>,
        contract_fields: &'a [ContractFieldAst<'i>],
        contract_constants: &'a HashMap<String, Expr<'i>>,
        contract_fields_end_offset: usize,
    ) -> Self {
        Self { structs, functions, contract_fields, contract_constants, contract_fields_end_offset }
    }
}
