use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Leaf {
    pub path: Vec<String>,
    pub type_ref: TypeRef,
}

pub fn flattened_struct_name(base: &str, path: &[String]) -> String {
    let mut out = String::from("__struct__");
    push_length_prefixed_name_part(&mut out, base);
    for part in path {
        out.push('_');
        push_length_prefixed_name_part(&mut out, part);
    }
    out
}

fn push_length_prefixed_name_part(out: &mut String, part: &str) {
    out.push_str(&part.len().to_string());
    out.push('_');
    out.push_str(part);
}

pub(super) fn flatten_struct_fields(
    type_ref: &TypeRef,
    structs: &StructRegistry,
    prefix: &mut Vec<String>,
    out: &mut Vec<Leaf>,
) -> Result<(), CompilerError> {
    if let Some(struct_name) = struct_name(type_ref, structs) {
        let item = structs.get(struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        for field in &item.fields {
            prefix.push(field.name.clone());
            flatten_struct_fields(&field.type_ref, structs, prefix, out)?;
            prefix.pop();
        }
    } else {
        out.push(Leaf { path: prefix.clone(), type_ref: type_ref.clone() });
    }
    Ok(())
}

pub(crate) fn flattened_struct_field_specs_for_type(
    type_ref: &TypeRef,
    structs: &StructRegistry,
) -> Result<Vec<TypeRef>, CompilerError> {
    let mut leaves = Vec::new();
    flatten_struct_fields(type_ref, structs, &mut Vec::new(), &mut leaves)?;
    Ok(leaves.into_iter().map(|leaf| leaf.type_ref).collect())
}

pub(crate) fn flatten_type_leaves(type_ref: &TypeRef, structs: &StructRegistry) -> Result<Vec<Leaf>, CompilerError> {
    if let Some(struct_name) = struct_array_name(type_ref, structs) {
        let outer_dims = type_ref.array_dims.clone();
        let item = structs.get(&struct_name).ok_or_else(|| CompilerError::Unsupported(format!("unknown struct '{struct_name}'")))?;
        let mut leaves = Vec::new();
        for field in &item.fields {
            let mut field_type = field.type_ref.clone();
            field_type.array_dims.extend(outer_dims.iter().cloned());
            for mut leaf in flatten_type_leaves(&field_type, structs)? {
                leaf.path.insert(0, field.name.clone());
                leaves.push(leaf);
            }
        }
        return Ok(leaves);
    }

    let mut leaves = Vec::new();
    flatten_struct_fields(type_ref, structs, &mut Vec::new(), &mut leaves)?;
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{ArrayDim, parse_contract_ast};

    #[test]
    fn nested_struct_array_layout_preserves_paths_and_array_dimensions() {
        let contract = parse_contract_ast(
            r#"
                contract C() {
                    struct Point {
                        int x;
                        byte[2] tag;
                    }
                    struct Item {
                        Point point;
                        bool active;
                    }
                    entry main() {}
                }
            "#,
        )
        .expect("contract should parse");
        let structs = build_struct_registry(&contract).expect("struct registry should build");
        let item_array = TypeRef { base: TypeBase::Custom("Item".to_string()), array_dims: vec![ArrayDim::Dynamic] };

        let leaves = flatten_type_leaves(&item_array, &structs).expect("layout should flatten");
        let actual = leaves.into_iter().map(|leaf| (leaf.path, leaf.type_ref.type_name())).collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                (vec!["point".to_string(), "x".to_string()], "int[]".to_string()),
                (vec!["point".to_string(), "tag".to_string()], "byte[2][]".to_string()),
                (vec!["active".to_string()], "bool[]".to_string()),
            ]
        );
    }

    #[test]
    fn flattened_names_distinguish_nested_paths_from_underscored_fields() {
        let nested = flattened_struct_name("o", &["a".to_string(), "b".to_string()]);
        let underscored = flattened_struct_name("o", &["a_b".to_string()]);

        assert_eq!(nested, "__struct__1_o_1_a_1_b");
        assert_eq!(underscored, "__struct__1_o_3_a_b");
    }
}
