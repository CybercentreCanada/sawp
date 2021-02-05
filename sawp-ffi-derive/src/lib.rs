//! A proc_macro for generating accessors for members of structs and enums
//!
//! Accessors are compatible with cbindgen for creating FFI
//!
//! Attributes: `#[sawp_ffi(...)]`
//! - `copy`: Return `Type` instead of `*const Type`.
//!           Useful for enums with `repr(Integer)`
//! - `skip`: Don't generate accessor for member.
//!           Note: only public members will have accessors.
//! - `u8_flag`: Return `u8` instead of `*const Type`.
//!            Requires member type to be using bitflags macro.
//! - `type_only`: Only generate enum `Type` and `<enum>_get_type`.
//!             Won't generate accessors for variant fields
//! - `prefix`: Prefix for all functions.
//!             eg: `<prefix>_<struct_name>_get_<field>`
//!
//! Note: accessors are functions so they will be in snake_case.
//! Struct and Enum names will be converted to snake_case in function names.
//!
//! ## Structs
//! Accessors for structs are of the form:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn struct_name_get_member_name(*const Struct) -> *const Member;
//! ```
//!
//! of if either the Member type is a field convertible to a C_FIELD by cbindgen or
//! has the sawp_ffi copy attribute:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn struct_name_get_member_name(*const Struct) -> Member;
//! ```
//!
//! ### Example
//! ```
//! extern crate bitflags;
//! use bitflags::bitflags;
//! use sawp_ffi_derive::GenerateFFI;
//!
//! #[repr(u16)]
//! #[derive(Copy, Clone)]
//! pub enum Version {
//!     Version1 = 0x0100,
//!     Version1_1 = 0x0101,
//!     Version2 = 0x0200,
//! }
//!
//! bitflags! {
//!     pub struct FileType: u8 {
//!         const READ = 0b0000_0000;
//!         const WRITE = 0b0000_0001;
//!     }
//! }
//!
//! #[derive(GenerateFFI)]
//! #[sawp_ffi(prefix = "sawp")]
//! pub struct MyStruct {
//!     pub num: usize,
//!     #[sawp_ffi(copy)]
//!     pub version: Version,
//!     #[sawp_ffi(u8_flag)]
//!     pub file_type: FileType,
//!     private: usize,
//!     #[sawp_ffi(skip)]
//!     pub skipped: usize,
//!     pub complex: Vec<u8>,
//! }
//! ```
//! Will result in:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn sawp_my_struct_get_num(my_struct: *const MyStruct) -> usize;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn sawp_my_struct_get_version(my_struct: *const MyStruct) -> Version;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn sawp_my_struct_get_file_type(my_struct: *const MyStruct) -> u8;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn sawp_my_struct_get_complex(my_struct: *const MyStruct) -> *const Vec<u8>;
//! ```
//!
//! ## Enums
//! Enums will have a flat, C compatible, enum created to define their type.
//! Users of the accessors should first call `<enum>_get_type()` to determine the enum type
//! and then use the appropriate accessors to get that type's fields.
//! These enums will have the same name as the base enum with Type appended to it.
//!
//! Note: All enum accessors can return null if the accessor isn't of the correct variant type
//!
//! Accessors for enums are of the form:
//!
//! To get the type:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn enum_name_get_type(* const Enum) -> EnumType;
//! ```
//!
//! For variants with named fields:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn enum_name_get_variant_name_member_name(e: *const Enum) -> *const Field;
//! ```
//!
//! For variants with a single unnamed field:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn enum_name_get_variant_name(e: *const Enum) -> *const Field;
//! ```
//!
//! For variants with multiple unnamed fields, N is the field index:
//!
//! ``` ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn enum_name_get_variant_name_N(e: *const Enum) -> *const Field;
//! ```
//!
//! Unit variants (variants with no fields) will not have any accessors.
//!
//! ### Example
//! ```
//! extern crate bitflags;
//! use bitflags::bitflags;
//! use sawp_ffi_derive::GenerateFFI;
//!
//! #[repr(u16)]
//! #[derive(Copy, Clone)]
//! pub enum Version {
//!     Version1 = 0x0100,
//!     Version1_1 = 0x0101,
//!     Version2 = 0x0200,
//! }
//!
//! bitflags! {
//!     pub struct FileType: u8 {
//!         const READ = 0b0000_0000;
//!         const WRITE = 0b0000_0001;
//!     }
//! }
//!
//! #[derive(GenerateFFI)]
//! pub enum MyEnum {
//!      UnnamedSingle(u8),
//!      UnnamedMultiple(u8, u16),
//!      Named {
//!         a: u8,
//!         b: Vec<u8>,
//!         #[sawp_ffi(u8_flag)]
//!         file_type: FileType,
//!      },
//!      Empty,
//! }
//! ```
//!
//! Will result in:
//! ``` ignore
//! #[repr(C)]
//! pub enum MyEnumType {
//!     UnnamedSingle,
//!     UnnamedMultiple,
//!     Named,
//!     Empty,
//! }
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn my_enum_get_unnamed_single(my_enum: *const MyEnum) -> *const u8;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn my_enum_get_unnamed_multiple_0(my_enum: *const MyEnum) -> *const u8;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn my_enum_get_unnamed_multiple_1(my_enum: *const MyEnum) -> *const u16;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn my_enum_get_named_a(my_enum: *const MyEnum) -> *const u8;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn my_enum_get_named_b(my_enum: *const MyEnum) -> *const Vec<u8>;
//!
//! #[no_mangle]
//! pub unsafe extern "C" fn my_enum_get_named_file_type(my_enum: *const MyEnum) -> *const u8;
//! ```

extern crate proc_macro;

use heck::SnakeCase;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Derive macro for autogenerated accessors compatible with cbindgen
/// See library documentation for usage examples
#[proc_macro_derive(GenerateFFI, attributes(sawp_ffi))]
pub fn derive_sawp_ffi(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    impl_sawp_ffi(&ast).into()
}

fn impl_sawp_ffi(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let ffi_metas: Vec<syn::NestedMeta> = ast
        .attrs
        .iter()
        .flat_map(|attr| get_ffi_meta(attr))
        .collect();
    let prefix = get_ffi_prefix(&ffi_metas);
    match &ast.data {
        syn::Data::Struct(data) => gen_struct_accessors(&prefix, &name, &data),
        syn::Data::Enum(data) => gen_enum_accessors(&prefix, &name, &data, &ffi_metas),
        syn::Data::Union(_) => panic!("syn::Data::Union not supported"),
    }
}

/// Fields that can be passed as value
const C_FIELDS: &[&str] = &[
    "u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize",
];

/// If type can be passed as value
fn is_cpp_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(ty) = ty {
        if let Some(ident) = ty.path.get_ident() {
            return C_FIELDS.contains(&ident.to_string().as_str());
        }
    }
    false
}

/// Get sawp_ffi meta tags
fn get_ffi_meta(attr: &syn::Attribute) -> Vec<syn::NestedMeta> {
    if !attr.path.is_ident("sawp_ffi") {
        return Vec::new();
    }

    if let Ok(syn::Meta::List(meta)) = attr.parse_meta() {
        meta.nested.into_iter().collect()
    } else {
        Vec::new()
    }
}

fn get_ffi_prefix(metas: &[syn::NestedMeta]) -> Option<String> {
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

/// Has given sawp_ffi attribute
fn has_ffi_meta(attribute: &str, metas: &[syn::NestedMeta]) -> bool {
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
fn has_ffi_copy_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("copy", metas)
}

/// Has sawp_ffi(skip) attribute
fn has_ffi_skip_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("skip", metas)
}

/// Has sawp_ffi(u8_flag) attribute
fn has_ffi_u8_flag_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("u8_flag", metas)
}

/// Has sawp_ffi(type_only) attribute
fn has_ffi_type_only_meta(metas: &[syn::NestedMeta]) -> bool {
    has_ffi_meta("type_only", metas)
}

/// Assign ptr to *ptr after checking it is not null
fn deref(field_name: &syn::Ident) -> TokenStream {
    quote! {
        let #field_name = if #field_name.is_null() {
            panic!(format!("{} is NULL in {}", stringify!(#field_name), line!()));
        } else {
            &*#field_name
        };
    }
}

/// Generate accessors for each field in data
/// Skips non-public fields and fields with skip tag
fn gen_struct_accessors(
    prefix: &Option<String>,
    name: &syn::Ident,
    data: &syn::DataStruct,
) -> TokenStream {
    let mut stream = TokenStream::new();

    if let syn::Fields::Named(fields) = &data.fields {
        for field in &fields.named {
            match &field.vis {
                syn::Visibility::Public(_) => (),
                _ => continue,
            }

            let ffi_metas: Vec<syn::NestedMeta> = field
                .attrs
                .iter()
                .flat_map(|attr| get_ffi_meta(attr))
                .collect();
            if has_ffi_skip_meta(&ffi_metas) {
                continue;
            }

            stream.extend(gen_field_accessor(
                &prefix,
                &ffi_metas,
                name,
                field.ident.as_ref().unwrap(),
                &field.ty,
            ));
        }
    }

    stream
}

/// Generate field accessor
/// If return type is a C Type or has tag copy return TYPE
/// Otherwise return *const TYPE
fn gen_field_accessor(
    prefix: &Option<String>,
    metas: &[syn::NestedMeta],
    struct_name: &syn::Ident,
    field: &syn::Ident,
    ty: &syn::Type,
) -> TokenStream {
    let struct_variable = struct_name.to_string().to_snake_case();
    let struct_variable = syn::Ident::new(&struct_variable, proc_macro2::Span::call_site());

    let func_name = match prefix {
        Some(prefix) => format_ident!("{}_{}_get_{}", prefix, struct_variable, field),
        None => format_ident!("{}_get_{}", struct_variable, field),
    };
    let deref_variable = deref(&struct_variable);
    if is_cpp_type(&ty) || has_ffi_copy_meta(&metas) {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#struct_variable: *const #struct_name) -> #ty {
                #deref_variable
                #struct_variable.#field
            }
        }
    } else if has_ffi_u8_flag_meta(&metas) {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#struct_variable: *const #struct_name) -> u8 {
                #deref_variable
                #struct_variable.#field.bits()
            }
        }
    } else {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#struct_variable: *const #struct_name) -> *const #ty {
                #deref_variable
                &#struct_variable.#field
            }
        }
    }
}

/// Generate match branch for enum variant
/// If match_variant is set, will bind that field as FIELD
fn gen_enum_named_match_branch(
    enum_name: &syn::Ident,
    variant: &syn::Variant,
    match_variant: Option<&syn::Ident>,
) -> TokenStream {
    let ident = &variant.ident;
    if let syn::Fields::Named(fields) = &variant.fields {
        let mut fields_stream = TokenStream::new();
        for field in &fields.named {
            let field = field.ident.as_ref().unwrap();
            match match_variant {
                Some(m) if m == field => {
                    fields_stream.extend(quote! { #field , });
                }
                _ => {
                    fields_stream.extend(quote! { #field : _, });
                }
            }
        }
        quote! { #enum_name::#ident{ #fields_stream } }
    } else {
        panic!("gen_enum_named_match_branch called on non-NamedFields");
    }
}

/// Generate match branch for enum variant
/// If match_variant is set, will bind that field as 'var'
fn gen_enum_unnamed_match_branch(
    enum_name: &syn::Ident,
    variant: &syn::Variant,
    match_variant: Option<usize>,
) -> TokenStream {
    let ident = &variant.ident;
    if let syn::Fields::Unnamed(fields) = &variant.fields {
        let mut fields_stream = TokenStream::new();
        for (i, _) in (&fields.unnamed).into_iter().enumerate() {
            match match_variant {
                Some(m) if m == i => fields_stream.extend(quote! { var, }),
                _ => fields_stream.extend(quote! { _, }),
            }
        }
        quote! { #enum_name::#ident( #fields_stream ) }
    } else {
        panic!("gen_enum_unnamed_match_branch called on non-UnnamedFields");
    }
}

/// Generate C Style enum
/// type will have the form ENUMType { VARIANT, ... }
fn gen_enum_type(
    prefix: &Option<String>,
    name: &syn::Ident,
    variants: &[&syn::Variant],
) -> TokenStream {
    let enum_variable = name.to_string().to_snake_case();
    let enum_variable = syn::Ident::new(&enum_variable, proc_macro2::Span::call_site());
    let enum_name = format_ident!("{}Type", name);

    let mut members = TokenStream::new();
    let mut matches = TokenStream::new();
    for variant in variants {
        let ident = &variant.ident;
        members.extend(quote! {#ident, });

        match &variant.fields {
            syn::Fields::Named(_) => {
                let match_branch = gen_enum_named_match_branch(name, variant, None);
                matches.extend(quote! { #match_branch => #enum_name::#ident, });
            }
            syn::Fields::Unnamed(_) => {
                let match_branch = gen_enum_unnamed_match_branch(name, variant, None);
                matches.extend(quote! { #match_branch => #enum_name::#ident, });
            }
            syn::Fields::Unit => {
                matches.extend(quote! { #name::#ident => #enum_name::#ident, });
            }
        }
    }

    let func_name = match prefix {
        Some(prefix) => format_ident!("{}_{}_get_type", prefix, enum_variable),
        None => format_ident!("{}_get_type", enum_variable),
    };

    let deref_variable = deref(&enum_variable);
    quote! {
        #[repr(C)]
        #[derive(Debug, PartialEq, Clone, Copy)]
        pub enum #enum_name {
            #members
        }

        /// # Safety
        /// function will panic if called with null
        #[no_mangle]
        pub unsafe extern "C" fn #func_name(#enum_variable: *const #name) -> #enum_name
        {
            #deref_variable
            match #enum_variable {
                #matches
            }
        }
    }
}

/// Generate enum type and accessors
fn gen_enum_accessors(
    prefix: &Option<String>,
    name: &syn::Ident,
    data: &syn::DataEnum,
    top_level_metas: &[syn::NestedMeta],
) -> TokenStream {
    let variants: Vec<&syn::Variant> = data.variants.iter().collect();
    let mut stream = gen_enum_type(prefix, name, &variants);

    if !has_ffi_type_only_meta(&top_level_metas) {
        for variant in variants {
            match &variant.fields {
                syn::Fields::Named(fields) => {
                    for field in &fields.named {
                        let ffi_metas: Vec<syn::NestedMeta> = field
                            .attrs
                            .iter()
                            .flat_map(|attr| get_ffi_meta(attr))
                            .collect();
                        if has_ffi_skip_meta(&ffi_metas) {
                            continue;
                        }

                        stream.extend(gen_enum_named_accessor(
                            prefix,
                            &ffi_metas,
                            name,
                            variant,
                            field.ident.as_ref().unwrap(),
                            &field.ty,
                        ));
                    }
                }
                syn::Fields::Unnamed(fields) => {
                    for (i, field) in (&fields.unnamed).into_iter().enumerate() {
                        let ffi_metas: Vec<syn::NestedMeta> = field
                            .attrs
                            .iter()
                            .flat_map(|attr| get_ffi_meta(attr))
                            .collect();
                        if has_ffi_skip_meta(&ffi_metas) {
                            continue;
                        }
                        stream.extend(gen_enum_unnamed_accessor(
                            prefix, &ffi_metas, name, variant, i, &field.ty,
                        ));
                    }
                }
                _ => (),
            }
        }
    }
    stream
}

/// Generate accessor for named enum
/// Will have the form ENUM_get_VARIANT_FIELD
fn gen_enum_named_accessor(
    prefix: &Option<String>,
    metas: &[syn::NestedMeta],
    enum_name: &syn::Ident,
    variant: &syn::Variant,
    field: &syn::Ident,
    ty: &syn::Type,
) -> TokenStream {
    let enum_variable = enum_name.to_string().to_snake_case();
    let enum_variable = syn::Ident::new(&enum_variable, proc_macro2::Span::call_site());
    let variant_name = &variant.ident.to_string().to_snake_case();
    let variant_name = syn::Ident::new(&variant_name, proc_macro2::Span::call_site());

    let func_name = match prefix {
        Some(prefix) => format_ident!(
            "{}_{}_get_{}_{}",
            prefix,
            enum_variable,
            variant_name,
            field
        ),
        None => format_ident!("{}_get_{}_{}", enum_variable, variant_name, field),
    };

    let match_branch = gen_enum_named_match_branch(enum_name, variant, Some(field));

    let deref_variable = deref(&enum_variable);
    if has_ffi_u8_flag_meta(&metas) {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#enum_variable: *const #enum_name) -> *const u8 {
                #deref_variable
                if let #match_branch = #enum_variable {
                    &#field.bits()
                } else {
                    std::ptr::null()
                }
            }
        }
    } else {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#enum_variable: *const #enum_name) -> *const #ty {
                #deref_variable
                if let #match_branch = #enum_variable {
                    #field
                } else {
                    std::ptr::null()
                }
            }
        }
    }
}

/// Generate accessor for unnamed enum
/// If enum only has a single member, will have the form ENUM_get_VARIANT
/// Otherwise ENUM_get_VARIANT_FIELD#
/// Returns *const TYPE
/// Generated function will return nullptr if called on wrong variant
fn gen_enum_unnamed_accessor(
    prefix: &Option<String>,
    metas: &[syn::NestedMeta],
    enum_name: &syn::Ident,
    variant: &syn::Variant,
    field: usize,
    ty: &syn::Type,
) -> TokenStream {
    let enum_variable = enum_name.to_string().to_snake_case();
    let enum_variable = syn::Ident::new(&enum_variable, proc_macro2::Span::call_site());
    let variant_name = &variant.ident.to_string().to_snake_case();
    let variant_name = syn::Ident::new(&variant_name, proc_macro2::Span::call_site());

    let func_name = match &variant.fields {
        syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => match prefix {
            Some(prefix) => format_ident!("{}_{}_get_{}", prefix, enum_variable, variant_name),
            None => format_ident!("{}_get_{}", enum_variable, variant_name),
        },
        _ => match prefix {
            Some(prefix) => format_ident!(
                "{}_{}_get_{}_{}",
                prefix,
                enum_variable,
                variant_name,
                field
            ),
            None => format_ident!("{}_get_{}_{}", enum_variable, variant_name, field),
        },
    };

    let match_branch = gen_enum_unnamed_match_branch(enum_name, variant, Some(field));
    let deref_variable = deref(&enum_variable);
    if has_ffi_u8_flag_meta(&metas) {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#enum_variable: *const #enum_name) -> *const u8 {
                #deref_variable
                if let #match_branch = #enum_variable {
                    &var.bits()
                } else {
                    std::ptr::null()
                }
            }
        }
    } else {
        quote! {
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #func_name(#enum_variable: *const #enum_name) -> *const #ty {
                #deref_variable
                if let #match_branch = #enum_variable {
                    var
                } else {
                    std::ptr::null()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_struct() {
        let input = r#"
            #[derive(GenerateFFI)]
            #[sawp_ffi(prefix = "sawp")]
            pub struct MyStruct {
                pub num: usize,
                #[sawp_ffi(copy)]
                pub version: Version,
                #[sawp_ffi(u8_flag)]
                pub file_type: FileType,
                private: usize,
                #[sawp_ffi(skip)]
                skipped: usize,
                pub complex: Vec<u8>,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }

    #[test]
    fn test_macro_enum() {
        let input = r#"
            #[derive(GenerateFFI)]
            pub enum MyEnum {
                 UnnamedSingle(u8),
                 UnnamedMultiple(u8, u16),
                 Named {
                    a: u8,
                    b: Vec<u8>,
                    #[sawp_ffi(u8_flag)]
                    file_type: FileType,
                 },
                 Empty,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }
}
