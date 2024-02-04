#[cfg_attr(all(target_os = "windows", target_arch = "x86"), path = "windows/x86.rs")]
#[cfg_attr(all(target_os = "windows", target_arch = "x86_64"), path = "windows/x86_64.rs")]
mod hook_impl;
pub(crate) mod util;

pub use hook_impl::*;
