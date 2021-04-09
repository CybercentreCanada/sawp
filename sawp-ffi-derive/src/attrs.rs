/// This module handles parsing of `#[sawp_ffi(...)]` attributes.

/// Get sawp_ffi meta attributes
pub fn get_ffi_meta(attr: &syn::Attribute) -> Vec<syn::NestedMeta> {
    if !attr.path.is_ident("sawp_ffi") {
        return Vec::new();
    }

    if let Ok(syn::Meta::List(meta)) = attr.parse_meta() {
        meta.nested.into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Get value of sawp_ffi(prefix) is set
pub fn get_ffi_prefix(metas: &[syn::NestedMeta]) -> Option<String> {
    for meta in metas {
        match meta {
            syn::NestedMeta::Meta(syn::Meta::NameValue(value)) if value.path.is_ident("prefix") => {
                match &value.lit {
                    syn::Lit::Str(s) => return Some(s.value()),
                    _ => panic!("sawp_ffi(prefix) expects string literal"),
                }
            }
            _ => (),
        }
    }
    None
}

/// Get value of sawp_ffi(flag) is set
pub fn get_ffi_flag(metas: &[syn::NestedMeta]) -> Option<syn::Type> {
    for meta in metas {
        match meta {
            syn::NestedMeta::Meta(syn::Meta::NameValue(value)) if value.path.is_ident("flag") => {
                return Some(parse_lit_into_ty("flag", &value.lit))
            }
            _ => (),
        }
    }
    None
}

/// Has given sawp_ffi attribute
pub fn has_ffi_meta(attribute: &str, metas: &[syn::NestedMeta]) -> bool {
    for meta in metas {
        match meta {
            syn::NestedMeta::Meta(syn::Meta::Path(word)) if word.is_ident(attribute) => {
                return true;
            }
            _ => (),
        }
    }
    false
}

/// Has sawp_ffi(copy) attribute
pub fn has_ffi_copy_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("copy", metas)
}

/// Has sawp_ffi(skip) attribute
pub fn has_ffi_skip_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("skip", metas)
}

/// Has sawp_ffi(type_only) attribute
pub fn has_ffi_type_only_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("type_only", metas)
}

fn parse_lit_into_ty(attr_name: &str, lit: &syn::Lit) -> syn::Type {
    if let syn::Lit::Str(lit) = lit {
        syn::parse_str(&lit.value())
            .unwrap_or_else(|_| panic!("couldn't parse value for {}: {:?}", attr_name, lit.value()))
    } else {
        panic!("expected attribute to be a string: {}", attr_name);
    }
}
