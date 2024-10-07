use quote::quote;
use syn::{parse_macro_input, Item, ItemStruct};

#[proc_macro_attribute]
pub fn raw_event_section(
    _: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: Item = parse_macro_input!(item);
    let output = quote! {
        #[derive(Default)]
        #[repr(C)]
        #input
    };
    output.into()
}

#[proc_macro_attribute]
pub fn event_section(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: ItemStruct = parse_macro_input!(item);
    let ident = &input.ident;

    let id: syn::Expr = syn::parse(args).expect("Invalid event id");

    let output = quote! {
        #[derive(Default)]
        #[crate::event_type]
        #input

        impl #ident {
            pub(crate) const SECTION_ID: u8 = #id as u8;
        }

        impl EventSectionInternal for #ident {
            fn id(&self) -> u8 {
                Self::SECTION_ID
            }

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

#[proc_macro_attribute]
pub fn event_section_factory(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: ItemStruct = parse_macro_input!(item);
    let ident = &input.ident;

    let id: syn::Expr = syn::parse(args).expect("Invalid factory id");

    let output = quote! {
        #input

        impl #ident {
            pub(crate) const FACTORY_ID: u8 = #id as u8;

        }

        impl EventSectionFactory for #ident {
            fn id(&self) -> u8 {
                Self::FACTORY_ID
            }

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any
                where Self: Sized,
            {
                self
            }
        }
    };
    output.into()
}
