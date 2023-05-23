use proc_macro::{self, TokenStream};
use proc_macro2;
use quote::quote;
use syn::*;

#[proc_macro_attribute]
pub fn event_section(
    _: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let output = format!(
        r#"
        #[serde_with::skip_serializing_none]
        #[derive(Default, serde::Serialize, serde::Deserialize, crate::EventSection)]
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

            fn to_json(&self) -> serde_json::Value
                where Self: serde::Serialize,
            {
                serde_json::json!(self)
            }
        }
    };
    output.into()
}

#[proc_macro_derive(EventSectionDisplay)]
pub fn derive_event_section_display(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);
    let fields_print: Vec<proc_macro2::TokenStream> = match data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields
            .named
            .into_iter()
            .filter(|field| {
                field.ident.is_some()
                    && match field.ty {
                        Type::Path(_) => true,
                        _ => false,
                    }
            })
            .map(|field| {
                // Unwrap as we filtered only Some() values.
                let ident = field.ident.unwrap();

                let get_type = |path: &TypePath| -> String {
                    path.path
                        .segments
                        .clone()
                        .into_iter()
                        .map(|seg| format!("{}", seg.ident))
                        .collect::<Vec<String>>()
                        .join("::")
                };

                // Use unimplemented as we filtered already.
                let Type::Path(path) = field.ty else { unimplemented!() };
                let r#type = get_type(&path);

                let format;
                match r#type.as_str() {
                    "bool" | "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64"
                    | "String" => format = "{}: {} ",
                    _ => format = "{}: {{ {}}} ",
                }

                // FIXME: did not find a way to get the type inside an Option...
                if r#type.as_str() == "Option" {
                    quote!(
                        if self.#ident.is_some() {
                            write!(f, #format, stringify!(#ident), self.#ident.as_ref().unwrap())?;
                        }
                    )
                } else {
                    quote!(write!(f, #format, stringify!(#ident), self.#ident)?;)
                }
            })
            .collect(),
        _ => panic!("derive(EventSection) only works on structs with named fields"),
    };

    let output = quote! {
        impl std::fmt::Display for #ident {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                #(#fields_print)*
                Ok(())
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
    let output = format!(
        r#"
        #[derive(crate::EventSectionFactory)]
        #[event_section({section})]
        {item}
    "#,
        section = args.to_string()
    );
    output
        .parse()
        .expect("Invalid tokens from event_section_factory macro")
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
