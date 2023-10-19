/// # Workaround
///
/// Provides workarounds to circumvent some limitations of Rust and/or
/// dependencies we use.
///
/// Currently libbpf_rs does not wrap libbpf_register_prog_handler.
///
/// For now we internally wrap it and consume it for inlining dynamic code.

#[derive(Clone, Debug, Default)]
pub(crate) struct ProgHandlerOpts {
    /// Custom user-provided value accessible in the callbacks, if needed.
    pub cookie: i64,
    pub setup_fn: libbpf_sys::libbpf_prog_setup_fn_t,
    pub prepare_load_fn: libbpf_sys::libbpf_prog_prepare_load_fn_t,
    pub attach_fn: libbpf_sys::libbpf_prog_attach_fn_t,
}

impl From<ProgHandlerOpts> for libbpf_sys::libbpf_prog_handler_opts {
    fn from(opts: ProgHandlerOpts) -> Self {
        let ProgHandlerOpts {
            cookie,
            setup_fn,
            prepare_load_fn,
            attach_fn,
        } = opts;

        libbpf_sys::libbpf_prog_handler_opts {
            sz: std::mem::size_of::<Self>() as u64,
            cookie,
            prog_setup_fn: setup_fn,
            prog_prepare_load_fn: prepare_load_fn,
            prog_attach_fn: attach_fn,
        }
    }
}

pub(crate) fn register_prog_handler(
    sec: Option<String>,
    prog_type: libbpf_rs::ProgramType,
    exp_attach_type: libbpf_rs::ProgramAttachType,
    opts: ProgHandlerOpts,
) -> std::io::Result<u32> {
    let opts = libbpf_sys::libbpf_prog_handler_opts::from(opts);

    let ret = match sec {
        Some(s) => {
            // Lifetime of the CString is bound to c_str to avoid
            // early drop as the pointer returned by as_ptr() is a raw
            // pointer. See the doc for further details.
            let c_str = std::ffi::CString::new(s)?;
            unsafe {
                libbpf_sys::libbpf_register_prog_handler(
                    c_str.as_ptr(),
                    prog_type as u32,
                    exp_attach_type as u32,
                    &opts as *const _,
                )
            }
        }
        None => unsafe {
            libbpf_sys::libbpf_register_prog_handler(
                core::ptr::null(),
                prog_type as u32,
                exp_attach_type as u32,
                &opts as *const _,
            )
        },
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(0)
}
