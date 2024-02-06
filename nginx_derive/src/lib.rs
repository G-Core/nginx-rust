/*
 * Copyright 2024 G-Core Innovations SARL
 */

use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::{format_ident, quote, quote_spanned};
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(NginxConfig)]
pub fn derive_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let output = impl_derive_config(input);

    proc_macro::TokenStream::from(output)
}

fn impl_derive_config(input: DeriveInput) -> proc_macro2::TokenStream {
    match input.data {
        syn::Data::Struct(s) => {
            let struct_name = input.ident;
            
            let mut field_defs: Vec<_> = s.fields.iter().filter_map(|f| {
                let name = f.ident.as_ref()?;
                let name_nil_terminated = Literal::byte_string((name.to_string() + "\0").as_bytes());
                let fn_name = format_ident!("set_{name}");
                let ty_name = &f.ty;
                

                Some(quote! {
                    ::nginx_module::ngx_command_t {
                        name: NgxStr::new_from_nil_terminated( #name_nil_terminated ).inner(),
                        type_: (::nginx_module::NGX_HTTP_MAIN_CONF | ::nginx_module::NGX_HTTP_SRV_CONF | ::nginx_module::NGX_HTTP_LOC_CONF | <#ty_name as ::nginx_module::ConfigValue >::ARITY.as_nginx_type())
                            as usize,
                        set: Some( #struct_name::#fn_name ),
                        conf: ::nginx_module::NGX_RS_HTTP_LOC_CONF_OFFSET,
                        offset: 0,
                        post: std::ptr::null_mut(),
                    }
                })
            }).collect();
            field_defs.push(quote! {
                ::nginx_module::NGX_RS_NULL_COMMAND
            });
            let field_count = field_defs.len();

            let set_methods = s.fields.iter().filter_map(|f| {
                let name = f.ident.as_ref()?;
                let fn_name = format_ident!("set_{name}");
                Some(quote!{
                    unsafe extern "C" fn #fn_name(
                        cf: *mut ::nginx_module::ngx_conf_t,
                        _cmd: *mut ::nginx_module::ngx_command_t,
                        conf: *mut std::ffi::c_void,
                    ) -> *mut i8 {
                        let start_ptr = (*(*cf).args).elts as *const ngx_str_t as *const NgxStr;
                        let count = (*(*cf).args).nelts;
                        let values = std::slice::from_raw_parts(start_ptr, count);
                        let conf = conf as *mut #struct_name;
                        let mut ngx_conf = NgxConfig::new(cf);

                        match ::nginx_module::ConfigValue::config_directive(&mut (*conf).#name, &mut ngx_conf, &values[1..]) {
                            Ok(()) => {
                                ::nginx_module::NGX_CONF_OK
                            }
                            Err(e) => {
                                b"Invalid value\0".as_ptr() as *mut i8
                            }
                        }
                    }
                })
            });

            let merge_fields = s.fields.iter().filter_map(|f| {
                let name = f.ident.as_ref()?;
                Some(quote!(
                    child.#name.merge(&parent.#name)
                ))
            });

            let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

            quote! {

                impl #impl_generics #struct_name #ty_generics #where_clause {
                    #(#set_methods)*

                    pub const fn commands() -> [ngx_command_t; #field_count] {
                        [ #(#field_defs),* ]
                    }

                    pub const COMMANDS_COUNT: usize = #field_count;

                    pub unsafe extern "C" fn create(conf: *mut ::nginx_module::ngx_conf_t) -> *mut std::ffi::c_void {
                        let pool = ::nginx_module::Pool::from_raw((*conf).pool);
                        let config = pool.alloc::<#struct_name>();
                        match config {
                            Err(e) => {
                                let log = ::nginx_module::Log::new((*conf).log);
                                log.error(e.to_string());
                                std::ptr::null_mut()
                            },
                            Ok(c) => (c as *mut #struct_name).cast(),
                        }
                    }

                    pub unsafe extern "C" fn merge(
                        _cf: *mut ngx_conf_t,
                        parent: *mut c_void,
                        child: *mut c_void,
                    ) -> *mut i8 {
                        use ::nginx_module::ConfigValue;

                        let parent = &*(parent as *mut #struct_name);
                        let child = &mut *(child as *mut #struct_name);

                        #(#merge_fields);*;

                        ::nginx_module::NGX_CONF_OK
                    }
                }
            }
        }
        syn::Data::Enum(e) => quote_spanned! {
            e.enum_token.span =>
            compile_error!("Config derive: expected a struct");
        },
        syn::Data::Union(u) => quote_spanned! {
            u.union_token.span =>
            compile_error!("Config derive: expected a struct");
        },
    }
}
