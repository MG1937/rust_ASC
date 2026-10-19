use crate::asc_core::findrefs::findrefs_manager::FindRefInput;
use crate::asc_core::findrefs::locator::field_locator::FieldFind;
use crate::asc_core::findrefs::locator::method_locator::MethodFind;

pub(crate) fn _format_class_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("Class name cannot be empty".to_owned());
    }
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
        return Ok(name.to_owned());
    }
    let mut name = name.replace('.', "/");
    if !name.starts_with('L') {
        name = format!("L{name}");
    }
    if !name.ends_with(';') {
        name.push(';');
    }
    Ok(name)
}

fn _normalize_class_query(name: Option<&str>, fuzzy: bool) -> Result<Option<String>, String> {
    let Some(name) = name else {
        return Ok(None);
    };
    if fuzzy {
        return Ok(Some(if name.contains('.') && !name.contains('/') {
            name.replace('.', "/")
        } else {
            name.to_owned()
        }));
    }
    _format_class_name(name).map(Some)
}

pub(crate) fn _build_member_find(
    key: &str,
    clz: Option<&str>,
    clz_fuzzy: bool,
    name: Option<&str>,
) -> Result<FindRefInput, String> {
    let clz = clz.filter(|value| !value.is_empty());
    let name = name.filter(|value| !value.is_empty());
    if clz.is_none() && name.is_none() {
        return Err(format!(
            "{key} query needs at least one of class or {key} name"
        ));
    }

    let class = _normalize_class_query(clz, clz_fuzzy)?.map(|value| (value, !clz_fuzzy));
    match key {
        "method" => Ok(FindRefInput {
            string: None,
            type_: None,
            method: Some(MethodFind::new(class, name.map(str::to_owned))),
            field: None,
        }),
        "field" => Ok(FindRefInput {
            string: None,
            type_: None,
            method: None,
            field: Some(FieldFind::new(class, name.map(str::to_owned))),
        }),
        _ => Err(format!("Unknown member type: {key}")),
    }
}
