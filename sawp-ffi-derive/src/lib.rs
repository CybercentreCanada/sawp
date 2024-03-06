//! A proc_macro for generating accessors for members of structs and enums
//!
//! Accessors are compatible with cbindgen for creating FFI
//!
//! Attributes: `#[sawp_ffi(...)]`
//! - `copy`: Return `Type` instead of `*const Type`.
//!           Useful for enums with `repr(Integer)`
//! - `skip`: Don't generate accessor for member.
//!           Note: only public members will have accessors.
//! - `flag` = `flag_repr`: Return `flag_repr` instead of `*const Type`
//!           `flag_repr` should be the `repr` type of `Flag`.
//!           Requires member type to be sawp_flags::Flags
//! - `type_only`: Only generate enum `Type` and `<enum>_get_type`.
//!             Won't generate accessors for variant fields
//! - `prefix` = `prefix`: Prefix for all functions.
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
//! use sawp_flags::{BitFlags, Flags, Flag};
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
//! #[repr(u8)]
//! #[derive(Copy, Clone, Debug, BitFlags)]
//! pub enum FileType {
//!     READ = 0b0000_0001,
//!     WRITE = 0b0000_0010,
//! }
//!
//! #[derive(GenerateFFI)]
//! #[sawp_ffi(prefix = "sawp")]
//! pub struct MyStruct {
//!     pub num: usize,
//!     #[sawp_ffi(copy)]
//!     pub version: Version,
//!     #[sawp_ffi(flag=u8)]
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
//! extern crate sawp_flags;
//! use sawp_flags::{BitFlags, Flags, Flag};
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
//! #[repr(u8)]
//! #[derive(Copy, Clone, Debug, BitFlags)]
//! pub enum FileType {
//!     READ = 0b0000_0001,
//!     WRITE = 0b0000_0010,
//! }
//!
//! #[derive(GenerateFFI)]
//! pub enum MyEnum {
//!      UnnamedSingle(u8),
//!      UnnamedMultiple(u8, u16),
//!      Named {
//!         a: u8,
//!         b: Vec<u8>,
//!         #[sawp_ffi(flag=u8)]
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
//! ## Special type handling
//!
//! ### Strings
//!
//! If the field type is a String, accessors to get the pointer
//! and length will be generated as well. They will be the field
//! accessor appended with _ptr/_len respectively.
//!
//! Note: Strings will not be null terminated
//!
//! ### Vector
//!
//! If the field type is a Vector, accessors to get the pointer
//! and length will be generated as well. They will be the field
//! accessor appended with _ptr/_len respectively.
//!
//! ### Options
//!
//! If the field type is an Option, the accessor will return a pointer.
//! If the Option has a value, the pointer will contain that value,
//! otherwise the pointer will be null
//!
//! ### sawp_flags::Flags
//!
//! If the field type is a sawp_flags::Flags, the accessor will return
//! the primative value, ie. the returned value by `.bits()`.

extern crate proc_macro;

mod attrs;
use crate::attrs::*;

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
    let ffi_metas: Vec<syn::NestedMeta> = ast.attrs.iter().flat_map(get_ffi_meta).collect();
    let prefix = get_ffi_prefix(&ffi_metas);
    match &ast.data {
        syn::Data::Struct(data) => gen_struct_accessors(&prefix, name, data),
        syn::Data::Enum(data) => gen_enum_accessors(&prefix, name, data, &ffi_metas),
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

/// If type is String or str
fn is_string_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(ty) = ty {
        if let Some(ident) = ty.path.get_ident() {
            return ident.to_string().as_str() == "String" || ident.to_string().as_str() == "str";
        }
    }
    false
}

/// Get outer and inner types of a generic data type
/// Returns `None` if there isn't exactly 1 generic
///
/// # Example
/// ```ignore
/// Vec<u8> -> Some(Vec, u8)
/// Option<String> -> Some(Option, String)
/// ```
fn split_generic(ty: &syn::Type) -> Option<(syn::Ident, syn::Ident)> {
    if let syn::Type::Path(ty) = ty {
        if let Some((ident, arg)) = split_generic_helper(ty) {
            if let Some(inner_ident) = arg.path.get_ident() {
                return Some((ident, (*inner_ident).clone()));
            }
        }
    }
    None
}

/// Get outer, mid and inner types of a generic data type
/// Returns `None` if there isn't exactly 2 generics
///
/// # Example
/// ```ignore
/// Vec<Vec<u8>> -> Some(Vec, Vec, u8)
/// ```
fn split_generic_multi(ty: &syn::Type) -> Option<(syn::Ident, syn::Ident, syn::Ident)> {
    if let syn::Type::Path(ty) = ty {
        if let Some((ident_1, arg)) = split_generic_helper(ty) {
            if let Some((ident_2, arg)) = split_generic_helper(&arg) {
                if let Some(ident_3) = arg.path.get_ident() {
                    return Some((ident_1, ident_2, (*ident_3).clone()));
                }
            }
        }
    }
    None
}

fn split_generic_helper(ty: &syn::TypePath) -> Option<(syn::Ident, syn::TypePath)> {
    let segment = &ty.path.segments.first().expect("Path with no segments");
    if let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments {
        if arguments.args.len() == 1 {
            if let syn::GenericArgument::Type(syn::Type::Path(arg)) = &arguments.args[0] {
                return Some((segment.ident.clone(), arg.clone()));
            }
        }
    }
    None
}

/// Assign ptr to *ptr after checking it is not null
fn deref(field_name: &syn::Ident) -> TokenStream {
    quote! {
        let #field_name = if #field_name.is_null() {
            panic!("{} is NULL in {}", stringify!(#field_name), line!());
        } else {
            &*#field_name
        };
    }
}

/// Alias representing return type information
/// 0: return Type
/// 1: return Value
///      eg: has pointer transformation or `.bits()` applied
type ReturnType = (TokenStream, TokenStream);

/// Determine return type and how to return field
/// always_ptr means type will never be returned as a Copy
/// Figure out what the return type should be
/// sawp_ffi(copy) || is_cpp_type -> Type
/// Option<Type> -> *const Type
/// sawp_flag::Flags<FlagType> -> FlagType::Primitive
/// _ -> *const Type
fn return_type(
    field: &TokenStream,
    ty: &syn::Type,
    metas: &[syn::NestedMeta],
    always_ptr: bool,
) -> ReturnType {
    get_ffi_flag(metas);
    if !always_ptr && (is_cpp_type(ty) || has_ffi_copy_meta(metas)) {
        (quote! {#ty}, quote! {#field})
    } else if let Some(flag_repr) = get_ffi_flag(metas) {
        let (outer, _) = split_generic(ty).unwrap_or_else(|| {
            panic!(
                "sawp_ffi(flag) must be used on sawp_flags::Flags type: {}",
                field
            )
        });
        if outer.to_string().as_str() != "Flags" {
            panic!(
                "sawp_ffi(flag) must be used on sawp_flags::Flags type: {}",
                field
            );
        }
        if always_ptr {
            (quote! {*const #flag_repr}, quote! { #field.bits_ref()})
        } else {
            (quote! {#flag_repr}, quote! {#field.bits()})
        }
    } else if let Some((outer, inner)) = split_generic(ty) {
        if outer.to_string().as_str() == "Option" {
            (
                quote! {*const #inner},
                quote! {
                    match #field.as_ref() {
                        Some(value) => value,
                        None => std::ptr::null(),
                    }
                },
            )
        } else if always_ptr {
            (quote! {*const #ty}, quote! {#field})
        } else {
            (quote! {*const #ty}, quote! {&#field})
        }
    } else if always_ptr {
        // Enum field already a ref
        (quote! {*const #ty}, quote! {#field})
    } else {
        (quote! {*const #ty}, quote! {&#field})
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

            let ffi_metas: Vec<syn::NestedMeta> =
                field.attrs.iter().flat_map(get_ffi_meta).collect();
            if has_ffi_skip_meta(&ffi_metas) {
                continue;
            }

            stream.extend(gen_field_accessor(
                prefix,
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
    let (ret_type, ret_var) = return_type(&quote! {#struct_variable.#field}, ty, metas, false);
    let mut accessors = quote! {
        /// # Safety
        /// function will panic if called with null
        #[no_mangle]
        pub unsafe extern "C" fn #func_name(#struct_variable: *const #struct_name) -> #ret_type {
            #deref_variable
            #ret_var
        }
    };

    if is_string_type(ty) {
        let ptr_name = format_ident!("{}_ptr", func_name);
        let len_name = format_ident!("{}_len", func_name);
        // Making assumption that ret_var is simple
        accessors.extend(quote! {
        /// Get ptr to data of `#struct_variable.#field`
        ///
        /// Note: String is not null terminated
        ///
        /// # Safety
        /// function will panic if called with null
        #[no_mangle]
        pub unsafe extern "C" fn #ptr_name(#struct_variable: *const #struct_name) -> *const u8 {
            #deref_variable
            (#ret_var).as_ptr()
        }

        /// Get length of `#struct_variable.#field`
        /// # Safety
        /// function will panic if called with null
        #[no_mangle]
        pub unsafe extern "C" fn #len_name(#struct_variable: *const #struct_name) -> usize {
            #deref_variable
            (#ret_var).len()
        }
        });
    } else if let Some((outer, inner)) = split_generic(ty) {
        if outer.to_string().as_str() == "Vec" {
            let ptr_name = format_ident!("{}_ptr", func_name);
            let len_name = format_ident!("{}_len", func_name);
            // Making assumption that ret_var is simple
            accessors.extend(quote! {
                /// Get ptr to data of `#struct_variable.#field`
                /// # Safety
                /// function will panic if called with null
                #[no_mangle]
                pub unsafe extern "C" fn #ptr_name(#struct_variable: *const #struct_name) -> *const #inner {
                    #deref_variable
                    (#ret_var).as_ptr()
                }

                /// Get length of `#struct_variable.#field`
                /// # Safety
                /// function will panic if called with null
                #[no_mangle]
                pub unsafe extern "C" fn #len_name(#struct_variable: *const #struct_name) -> usize {
                    #deref_variable
                    (#ret_var).len()
                }
            });
            if inner.to_string().as_str() != "u8" {
                let idx_name = format_ident!("{}_ptr_to_idx", func_name);
                accessors.extend(quote! {
                    /// Get ptr to member of `#struct_variable.#field` at index
                    /// # Safety
                    /// function will panic if called with null or an index outside bounds
                    #[no_mangle]
                    pub unsafe extern "C" fn #idx_name(#struct_variable: *const #struct_name, n: usize) -> *const #inner {
                        #deref_variable
                        (#ret_var[n])
                    }
                });
            }
        }
    } else if let Some((outer, mid, inner)) = split_generic_multi(ty) {
        if outer.to_string().as_str() == "Vec"
            && mid.to_string().as_str() == "Vec"
            && inner.to_string().as_str() == "u8"
        {
            let idx_name = format_ident!("{}_ptr_to_idx", func_name);
            accessors.extend(quote! {
                /// Get ptr to member of `#struct_variable.#field` at index
                /// # Safety
                /// function will panic if called with null or an index outside bounds
                #[no_mangle]
                pub unsafe extern "C" fn #idx_name(#struct_variable: *const #struct_name, n: usize) -> *const #inner {
                    #deref_variable
                    (#ret_var[n]).as_ptr()
                }
            });
        }
    }
    accessors
}

/// Generate match branch for enum variant
/// If match_variant is set, will bind that field as FIELD
#[allow(clippy::unneeded_field_pattern)]
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
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

    if !has_ffi_type_only_meta(top_level_metas) {
        for variant in variants {
            match &variant.fields {
                syn::Fields::Named(fields) => {
                    for field in &fields.named {
                        let ffi_metas: Vec<syn::NestedMeta> =
                            field.attrs.iter().flat_map(get_ffi_meta).collect();
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
                        let ffi_metas: Vec<syn::NestedMeta> =
                            field.attrs.iter().flat_map(get_ffi_meta).collect();
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
    let variant_name = syn::Ident::new(variant_name, proc_macro2::Span::call_site());

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
    let (ret_type, ret_var) = return_type(&quote! {#field}, ty, metas, true);
    let mut accessors = quote! {
        /// Get `#variant_name.#field`
        /// returns null if called on incorrect variant
        /// # Safety
        /// function will panic if called with null
        #[no_mangle]
        pub unsafe extern "C" fn #func_name(#enum_variable: *const #enum_name) -> #ret_type {
            #deref_variable
            if let #match_branch = #enum_variable {
                #ret_var
            } else {
                std::ptr::null()
            }
        }
    };

    if is_string_type(ty) {
        let ptr_name = format_ident!("{}_ptr", func_name);
        let len_name = format_ident!("{}_len", func_name);
        // Making assumption that ret_var is simple
        accessors.extend(quote! {
            /// Get ptr to data of `#field`
            /// returns null if called on incorrect variant
            ///
            /// Note: String is not null terminated
            ///
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #ptr_name(#enum_variable: *const #enum_name) -> *const u8 {
                #deref_variable
                if let #match_branch = #enum_variable {
                    #ret_var.as_ptr()
                } else {
                    std::ptr::null()
                }
            }

            /// Get length of `#field`
            /// returns 0 if called on incorrect variant
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #len_name(#enum_variable: *const #enum_name) -> usize {
                #deref_variable
                if let #match_branch = #enum_variable {
                    (#ret_var).len()
                } else {
                    0
                }
            }
        });
    } else if let Some((outer, inner)) = split_generic(ty) {
        if outer.to_string().as_str() == "Vec" {
            let ptr_name = format_ident!("{}_ptr", func_name);
            let len_name = format_ident!("{}_len", func_name);
            let idx_name = format_ident!("{}_ptr_to_idx", func_name);

            // Making assumption that ret_var is simple
            accessors.extend(quote! {
                /// Get ptr to data of `#field`
                /// returns null if called on incorrect variant
                /// # Safety
                /// function will panic if called with null
                #[no_mangle]
                pub unsafe extern "C" fn #ptr_name(#enum_variable: *const #enum_name) -> *const #inner {
                    #deref_variable
                    if let #match_branch = #enum_variable {
                        #ret_var.as_ptr()
                    } else {
                        std::ptr::null()
                    }
                }

                /// Get length of `#field`
                /// returns 0 if called on incorrect variant
                /// # Safety
                /// function will panic if called with null
                #[no_mangle]
                pub unsafe extern "C" fn #len_name(#enum_variable: *const #enum_name) -> usize {
                    #deref_variable
                    if let #match_branch = #enum_variable {
                        (#ret_var).len()
                    } else {
                        0
                    }
                }

                /// Get ptr to member of `#struct_variable.#field` at index
                /// # Safety
                /// function will panic if called with null or an index outside bounds
                #[no_mangle]
                pub unsafe extern "C" fn #idx_name(#enum_variable: *const Vec<#inner>, n: usize) -> *const #inner {
                    if !#enum_variable.is_null() {
                        &(*#enum_variable)[n]
                    }
                    else {
                        panic!("{} is NULL ", stringify!(#enum_variable));
                    }
                }
            });
        }
    }

    accessors
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
    let variant_name = syn::Ident::new(variant_name, proc_macro2::Span::call_site());

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
    let (ret_type, ret_var) = return_type(&quote! {var}, ty, metas, true);
    let mut accessors = quote! {
        /// Get `#variant_name.#field`
        /// returns null if called on incorrect variant
        /// # Safety
        /// function will panic if called with null
        #[no_mangle]
        pub unsafe extern "C" fn #func_name(#enum_variable: *const #enum_name) -> #ret_type {
            #deref_variable
            if let #match_branch = #enum_variable {
                #ret_var
            } else {
                std::ptr::null()
            }
        }
    };

    if is_string_type(ty) {
        let ptr_name = format_ident!("{}_ptr", func_name);
        let len_name = format_ident!("{}_len", func_name);
        // Making assumption that ret_var is simple
        accessors.extend(quote! {
            /// Get ptr to data of `#variant_name.#field`
            /// returns null if called on incorrect variant
            ///
            /// Note: String is not null terminated
            ///
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #ptr_name(#enum_variable: *const #enum_name) -> *const u8 {
                #deref_variable
                if let #match_branch = #enum_variable {
                    #ret_var.as_ptr()
                } else {
                    std::ptr::null()
                }
            }

            /// Get length of `#variant_name.#field`
            /// returns 0 if called on incorrect variant
            /// # Safety
            /// function will panic if called with null
            #[no_mangle]
            pub unsafe extern "C" fn #len_name(#enum_variable: *const #enum_name) -> usize {
                #deref_variable
                if let #match_branch = #enum_variable {
                    (#ret_var).len()
                } else {
                    0
                }
            }
        });
    } else if let Some((outer, inner)) = split_generic(ty) {
        if outer.to_string().as_str() == "Vec" {
            let ptr_name = format_ident!("{}_ptr", func_name);
            let len_name = format_ident!("{}_len", func_name);
            let idx_name = format_ident!("{}_ptr_to_idx", func_name);

            // Making assumption that ret_var is simple
            accessors.extend(quote! {
                /// Get ptr to data of `#variant_name.#field`
                /// returns null if called on incorrect variant
                /// # Safety
                /// function will panic if called with null
                #[no_mangle]
                pub unsafe extern "C" fn #ptr_name(#enum_variable: *const #enum_name) -> *const #inner {
                    #deref_variable
                    if let #match_branch = #enum_variable {
                        #ret_var.as_ptr()
                    } else {
                        std::ptr::null()
                    }
                }

                /// Get length of `#variant_name.#field`
                /// returns 0 if called on incorrect variant
                /// # Safety
                /// function will panic if called with null
                #[no_mangle]
                pub unsafe extern "C" fn #len_name(#enum_variable: *const #enum_name) -> usize {
                    #deref_variable
                    if let #match_branch = #enum_variable {
                        (#ret_var).len()
                    } else {
                        0
                    }
                }

                /// Get ptr to member of `#struct_variable.#field` at index
                /// # Safety
                /// function will panic if called with null or an index outside bounds
                #[no_mangle]
                pub unsafe extern "C" fn #idx_name(#enum_variable: *const Vec<#inner>, n: usize) -> *const #inner {
                    if !#enum_variable.is_null() {
                        &(*#enum_variable)[n]
                    }
                    else {
                        panic!("{} is NULL ", stringify!(#enum_variable));
                    }
                }
            });
        }
    }

    accessors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_struct() {
        let input = r#"
            #[sawp_ffi(prefix = "sawp")]
            pub struct MyStruct {
                pub num: usize,
                #[sawp_ffi(copy)]
                pub version: Version,
                #[sawp_ffi(flag = "u8")]
                pub file_type: Flags<FileType>,
                private: usize,
                #[sawp_ffi(skip)]
                skipped: usize,
                pub complex: Vec<u8>,
                pub string: String,
                pub option: Option<u8>,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }

    #[test]
    fn test_macro_enum() {
        let input = r#"
            pub enum MyEnum {
                UnnamedSingle(u8),
                UnnamedMultiple(String, Vec<u8>),
                Named {
                    a: u8,
                    b: Vec<u8>,
                    c: String,
                    d: Option<u8>,
                    #[sawp_ffi(flag = "u8")]
                    file_type: Flags<FileType>,
                },
                Empty,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }

    #[test]
    fn test_macro_struct_multi() {
        let input = r#"
            #[sawp_ffi(prefix = "sawp")]
            pub struct MyStructMulti {
                pub num: usize,
                #[sawp_ffi(copy)]
                pub version: Version,
                #[sawp_ffi(flag = "u8")]
                pub file_type: Flags<FileType>,
                private: usize,
                #[sawp_ffi(skip)]
                skipped: usize,
                pub complex: Vec<Vec<u8>>,
                pub string: String,
                pub option: Option<u8>,
            }
	"#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }

    #[test]
    #[should_panic(expected = "expects string literal")]
    fn test_macro_prefix_panic() {
        let input = r#"
            #[sawp_ffi(prefix = 0)]
            pub struct MyStruct {
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }

    #[test]
    #[should_panic(
        expected = "sawp_ffi(flag) must be used on sawp_flags::Flags type: my_struct . file_type"
    )]
    fn test_macro_flag_panic() {
        let input = r#"
            #[sawp_ffi(prefix = "sawp")]
            pub struct MyStruct {
                #[sawp_ffi(flag = "u8")]
                pub file_type: FileType,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }

    #[test]
    #[should_panic(expected = "Union not supported")]
    fn test_macro_union_panic() {
        let input = r#"
            pub union MyUnion {
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_ffi(&parsed);
    }
}
