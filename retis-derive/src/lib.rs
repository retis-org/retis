use quote::quote;
use syn::{parse_macro_input, Fields, Ident, Item, ItemStruct};

#[proc_macro_attribute]
pub fn event_section(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: Item = parse_macro_input!(item);
    let ident = match input {
        Item::Struct(ref item) => item.ident.clone(),
        Item::Enum(ref item) => item.ident.clone(),
        _ => panic!("event types must be enums or structs"),
    };

    let id: syn::Expr = syn::parse(args).expect("Invalid event id");

    let output = quote! {
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

            #[cfg(feature = "python")]
            fn to_py(&self, py: pyo3::Python<'_>) -> pyo3::PyObject {
                use pyo3::IntoPyObject;
                self.clone().into_pyobject(py).unwrap().into_any().unbind()
            }
        }

        #[cfg_attr(feature = "python", pyo3::pymethods)]
        #[cfg(feature = "python")]
        impl #ident {
            fn raw(&self, py: pyo3::Python<'_>) -> pyo3::PyObject {
                crate::python::to_pyobject(&self.to_json(), py)
            }

            fn show(&self) -> String {
                let format = crate::DisplayFormat::new().multiline(true);
                format!("{}", self.display(&format, &crate::FormatterConf::new()))
            }
        }
    };
    output.into()
}

struct EventTypeProps {
    ident: Ident,
    enum_is_simple: bool,
    named_fields: bool,
}

fn item_get_props(item: &Item) -> EventTypeProps {
    let mut enum_is_simple = false;
    let named_fields;

    let ident = match item {
        Item::Struct(item) => {
            named_fields = matches!(&item.fields, Fields::Named(_));
            item.ident.clone()
        }
        Item::Enum(item) => {
            named_fields = item
                .variants
                .iter()
                .all(|v| matches!(v.fields, Fields::Named(_)));
            enum_is_simple = item.variants.iter().all(|v| v.fields == Fields::Unit);
            item.ident.clone()
        }
        _ => panic!("event types must be enums or structs"),
    };
    EventTypeProps {
        ident,
        enum_is_simple,
        named_fields,
    }
}

#[proc_macro_attribute]
pub fn event_type(
    _args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: Item = parse_macro_input!(item);
    let props = item_get_props(&input);
    let mut pyclass_args = Vec::new();
    let mut derives = vec![
        quote!(Clone),
        quote!(Debug),
        quote!(serde::Serialize),
        quote!(serde::Deserialize),
    ];

    if props.enum_is_simple {
        // Simple enums need to be passed extra arguments so equality is implemented
        // using underlying integers: See https://pyo3.rs/main/doc/pyo3/attr.pyclass.html.
        pyclass_args.push(quote!(eq));
        pyclass_args.push(quote!(eq_int));
        derives.push(quote!(PartialEq))
    } else if props.named_fields {
        // Generate getters to all named fields.
        pyclass_args.push(quote!(get_all));
    }
    let ident = &props.ident;

    let output = quote! {
        #[cfg_attr(feature = "python", pyo3::pyclass(#(#pyclass_args),*))]
        #[serde_with::skip_serializing_none]
        #[derive(#(#derives),*)]
        #input

        #[cfg_attr(feature = "python", pyo3::pymethods)]
        #[cfg(feature = "python")]
        impl #ident {
            fn __repr__(&self, py: pyo3::Python<'_>) -> String {
                format!("{:?}", self)
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
