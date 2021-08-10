extern crate proc_macro;
use proc_macro2::{Ident, Span, TokenStream, TokenTree};
use quote::quote;

#[proc_macro_derive(BitFlags)]
pub fn derive_sawp_flags(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    impl_sawp_flags(&ast).into()
}

fn impl_sawp_flags(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let repr = if let Some(repr) = get_repr(ast) {
        repr
    } else {
        panic!("BitFlags enum must have a `repr` attribute with numeric argument");
    };
    match &ast.data {
        syn::Data::Enum(data) => impl_enum_traits(name, &repr, data),
        _ => panic!("Bitflags is only supported on enums"),
    }
}

fn get_repr(ast: &syn::DeriveInput) -> Option<Ident> {
    ast.attrs.iter().find_map(|attr| {
        if let Some(path) = attr.path.get_ident() {
            if path == "repr" {
                if let Some(tree) = attr.tokens.clone().into_iter().next() {
                    match tree {
                        TokenTree::Group(group) => {
                            if let Some(ident) = group.stream().into_iter().next() {
                                match ident {
                                    TokenTree::Ident(ident) => Some(ident),
                                    _ => None,
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    })
}

fn impl_enum_traits(name: &syn::Ident, repr: &Ident, data: &syn::DataEnum) -> TokenStream {
    // TODO: compile error when these items are reused.
    let list_items = data.variants.iter().map(|variant| &variant.ident);
    let list_all = list_items.clone();
    let display_items = list_items.clone();
    let from_str_items = list_items.clone();
    let from_str_items_str = list_items.clone().map(|variant| {
        Ident::new(
            variant.to_string().to_lowercase().as_str(),
            Span::call_site(),
        )
    });

    quote! {
        impl Flag for #name {
            type Primitive = #repr;

            const ITEMS: &'static [Self] = &[#(#name::#list_items),*];

            fn bits(self) -> Self::Primitive {
                self as #repr
            }

            fn none() -> Flags<Self> {
                Flags::from_bits(0)
            }

            fn all() -> Flags<Self> {
                Flags::from_bits(#(#name::#list_all as Self::Primitive)|*)
            }
        }

        impl std::ops::BitOr for #name {
            type Output = Flags<#name>;

            fn bitor(self, other: Self) -> Self::Output {
                Flags::from_bits(self.bits() | other.bits())
            }
        }

        impl std::ops::BitAnd for #name {
            type Output = Flags<#name>;

            fn bitand(self, other: Self) -> Self::Output {
                Flags::from_bits(self.bits() & other.bits())
            }
        }

        impl std::ops::BitXor for #name {
            type Output = Flags<#name>;

            fn bitxor(self, other: Self) -> Self::Output {
                Flags::from_bits(self.bits() ^ other.bits())
            }
        }

        impl std::ops::Not for #name {
            type Output = Flags<#name>;

            fn not(self) -> Self::Output {
                Flags::from_bits(!self.bits())
            }
        }

        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let empty = self.bits() == Self::none().bits();
                let mut first = true;
                #(
                    if self.bits() & #name::#display_items.bits() == #name::#display_items.bits() {
                        write!(f, "{}{}", if first { "" } else { " | " }, stringify!(#display_items))?;
                        first = false;

                        if empty {
                            return Ok(());
                        }
                    }
                )*

                if empty {
                    write!(f, "NONE")?;
                }

                Ok(())
            }
        }

        impl std::str::FromStr for #name {
            type Err = ();
            fn from_str(val: &str) -> std::result::Result<#name, Self::Err> {
                match val.to_lowercase().as_str() {
                    #(stringify!(#from_str_items_str) => Ok(#name::#from_str_items),)*
                    _ => Err(()),
                }
            }
        }

        impl PartialEq<Flags<Self>> for #name {
            fn eq(&self, other: &Flags<Self>) -> bool {
                self.bits() == other.bits()
            }
        }

        impl std::fmt::Binary for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Binary::fmt(&self.bits(), f)
            }
        }
    }
}

/// BitFlags derive macro tests
///
/// `#[derive(BitFlags)]` can't be used here and `impl_sawp_flags`
/// is being called directly instead.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_enum() {
        let input = r#"
            #[repr(u8)]
            enum Test {
                A = 0b0000,
                B = 0b0001,
                C = 0b0010,
                D = 0b0100,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_flags(&parsed);
    }

    #[test]
    #[should_panic(expected = "BitFlags enum must have a `repr` attribute")]
    fn test_macro_repr_panic() {
        let input = r#"
            enum Test {
                A = 0b0000,
                B = 0b0001,
                C = 0b0010,
                D = 0b0100,
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_flags(&parsed);
    }

    #[test]
    #[should_panic(expected = "Bitflags is only supported on enums")]
    fn test_macro_not_enum_panic() {
        let input = r#"
            #[repr(u8)]
            struct Test {
            }
        "#;
        let parsed: syn::DeriveInput = syn::parse_str(input).unwrap();
        impl_sawp_flags(&parsed);
    }
}
