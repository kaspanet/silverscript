use super::*;

#[derive(Clone)]
pub(crate) struct StructFieldSpec {
    pub(crate) name: String,
    pub(crate) type_ref: TypeRef,
}

#[derive(Clone)]
pub(crate) struct StructSpec {
    pub(crate) fields: Vec<StructFieldSpec>,
}

pub(crate) type StructRegistry = HashMap<String, StructSpec>;

pub(crate) fn build_struct_registry<'i>(contract: &ContractAst<'i>) -> Result<StructRegistry, CompilerError> {
    let mut registry = HashMap::new();
    for item in &contract.structs {
        if item.name == STATE_TYPE_NAME {
            return Err(CompilerError::Unsupported(format!("'{}' is a reserved struct name", STATE_TYPE_NAME)));
        }
        let mut names = HashSet::new();
        let fields = item
            .fields
            .iter()
            .map(|field| {
                if !names.insert(field.name.clone()) {
                    return Err(CompilerError::Unsupported(format!("duplicate struct field '{}.{}'", item.name, field.name)));
                }
                Ok(StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
            })
            .collect::<Result<Vec<_>, CompilerError>>()?;
        if registry.insert(item.name.clone(), StructSpec { fields }).is_some() {
            return Err(CompilerError::Unsupported(format!("duplicate struct name: {}", item.name)));
        }
    }

    let mut state_field_names = HashSet::new();
    let state_fields = contract
        .fields
        .iter()
        .map(|field| {
            if !state_field_names.insert(field.name.clone()) {
                return Err(CompilerError::Unsupported(format!("duplicate contract field name: {}", field.name)));
            }
            Ok(StructFieldSpec { name: field.name.clone(), type_ref: field.type_ref.clone() })
        })
        .collect::<Result<Vec<_>, CompilerError>>()?;
    registry.insert(STATE_TYPE_NAME.to_string(), StructSpec { fields: state_fields });

    Ok(registry)
}

pub(crate) fn struct_name<'a>(type_ref: &'a TypeRef, structs: &'a StructRegistry) -> Option<&'a str> {
    if type_ref.is_array() {
        return None;
    }

    match &type_ref.base {
        TypeBase::Custom(name) if structs.contains_key(name) => Some(name.as_str()),
        _ => None,
    }
}

pub fn is_struct(type_ref: &TypeRef, structs: &StructRegistry) -> bool {
    struct_name(type_ref, structs).is_some()
}

pub(crate) fn struct_array_name(type_ref: &TypeRef, structs: &StructRegistry) -> Option<String> {
    let element_type = type_ref.array_element_type()?;
    struct_name(&element_type, structs).map(ToOwned::to_owned)
}

pub fn is_struct_array(type_ref: &TypeRef, structs: &StructRegistry) -> bool {
    struct_array_name(type_ref, structs).is_some()
}

pub(super) fn is_struct_like(type_ref: &TypeRef, structs: &StructRegistry) -> bool {
    is_struct(type_ref, structs) || is_struct_array(type_ref, structs)
}

pub(crate) fn ensure_known_struct_or_builtin_type(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    context: &str,
) -> Result<(), CompilerError> {
    if !type_ref.is_array() {
        match &type_ref.base {
            TypeBase::Custom(name) if !structs.contains_key(name) => {
                return Err(CompilerError::Unsupported(format!("unknown type '{}' in {context}", name)));
            }
            _ => {}
        }
    } else if let TypeBase::Custom(name) = &type_ref.base {
        if structs.contains_key(name) {
            return Err(CompilerError::Unsupported(format!("arrays of struct type '{}' are not supported", name)));
        }
        return Err(CompilerError::Unsupported(format!("unknown type '{}' in {context}", name)));
    }
    Ok(())
}

pub(crate) fn validate_struct_graph(structs: &StructRegistry) -> Result<(), CompilerError> {
    fn visit(
        name: &str,
        structs: &StructRegistry,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> Result<(), CompilerError> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_string()) {
            return Err(CompilerError::Unsupported(format!("cyclic struct definition involving '{name}'")));
        }
        let item = structs.get(name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{name}'")))?;
        for field in &item.fields {
            ensure_known_struct_or_builtin_type(&field.type_ref, structs, "struct field")?;
            if let Some(child) = struct_name(&field.type_ref, structs) {
                visit(child, structs, visiting, visited)?;
            }
        }
        visiting.remove(name);
        visited.insert(name.to_string());
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for name in structs.keys() {
        visit(name, structs, &mut visiting, &mut visited)?;
    }
    Ok(())
}
