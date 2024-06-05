use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, ItemStruct};

#[proc_macro_attribute]
pub fn event_section(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: ItemStruct = parse_macro_input!(item);
    let ident = &input.ident;

    let name: syn::LitStr = syn::parse(args).expect("Invalid event name");

    let output = quote! {
        #[derive(Default, crate::EventSection)]
        #[crate::event_type]
        #input

        impl #ident {
            pub(crate) const SECTION_NAME: &'static str = #name;
        }
    };
    output.into()
}

#[proc_macro_attribute]
pub fn event_type(
    _: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let output = format!(
        r#"
        #[serde_with::skip_serializing_none]
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        {item}
    "#
    );
    output
        .parse()
        .expect("Invalid tokens from event_section macro")
}

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

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any
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
    let input: DeriveInput = parse_macro_input!(input);
    let ident = &input.ident;

    let output = quote! {
        impl EventSectionFactory for #ident {
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any
                where Self: Sized,
            {
                self
            }
        }
    };
    output.into()
}
