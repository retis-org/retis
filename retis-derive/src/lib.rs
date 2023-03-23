use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(EventSection)]
pub fn derive_event_section(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl EventSectionInternal for #ident {
            fn as_any(&self) -> &dyn std::any::Any
                where Self: Sized,
            {
                self
            }

            fn to_json(&self) -> serde_json::Value
                where Self: serde::Serialize,
            {
                serde_json::json!(self)
            }
        }
    };
    output.into()
}

#[proc_macro_derive(EventSectionFactory)]
pub fn derive_event_section_factory(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl EventSectionFactory for #ident {
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any
                where Self: Sized,
            {
                self
            }
        }
        impl SerdeEventSectionFactory for #ident {
            fn from_json(&self, val: serde_json::Value) -> Result<Box<dyn EventSection>>
                where Self: for<'a> serde::Deserialize<'a>,
            {
                Ok(Box::new(serde_json::from_value::<Self>(val)?))
            }
        }
    };
    output.into()
}
