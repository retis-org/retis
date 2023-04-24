use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput};

#[proc_macro_attribute]
pub fn event_section(
    _: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let output = format!(r#"
        #[serde_with::skip_serializing_none]
        #[derive(Default, serde::Serialize, serde::Deserialize, crate::EventSection)]
        {item}
    "#);
    output.parse().expect("Invalid tokens from event_section macro")
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

            fn to_json(&self) -> serde_json::Value
                where Self: serde::Serialize,
            {
                serde_json::json!(self)
            }
        }
    };
    output.into()
}

#[proc_macro_attribute]
pub fn event_section_factory(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let output = format!(r#"
        #[derive(crate::EventSectionFactory)]
        #[event_section({section})]
        {item}
    "#, section = args.to_string());
    output.parse().expect("Invalid tokens from event_section_factory macro")
}

#[proc_macro_derive(EventSectionFactory, attributes(event_section))]
pub fn derive_event_section_factory(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let ident = &input.ident;

    let default_section: syn::Attribute = parse_quote! {
        #[event_section(Self)]
    };
    let event_section: syn::Expr = (|| {
        for attr in input.attrs.iter() {
            if attr.path().is_ident("event_section") {
                return attr;
            }
        }
        &default_section
    })()
    .parse_args()
    .unwrap();

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
                where #event_section: for<'a> serde::Deserialize<'a>,
            {
                Ok(Box::new(serde_json::from_value::<#event_section>(val)?))
            }
        }
    };
    output.into()
}
