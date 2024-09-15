use log::{debug, error, info};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, WIN32_ERROR},
        System::Memory::{
            VirtualProtect, PAGE_EXECUTE_READWRITE,
            PAGE_PROTECTION_FLAGS,
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    VirtualAllocFailed(WIN32_ERROR),
    VirtualProtectFailed(WIN32_ERROR),
    VirtualQueryFailed(WIN32_ERROR),
}

#[derive(Debug)]
pub struct CallRel32Hook {
    module: PCSTR,
    offset: usize,
    old_rel32: u32,
}

unsafe impl Send for CallRel32Hook {}

pub unsafe fn hook_call_rel32(module: PCSTR, offset: usize, new_address: usize) -> Result<CallRel32Hook, HookError> {
    let call_base = GetModuleHandleA(module).unwrap();
    let call_address = call_base.0 as usize + offset;
    info!("Hooking rel32 call at {call_address:#016x} to {new_address:#016x}");

    debug!("Patching {:#08x} to call address {:#x}", call_address, new_address);
    let mut old_flags: PAGE_PROTECTION_FLAGS = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    if !VirtualProtect(call_address as _, 4, PAGE_EXECUTE_READWRITE, &mut old_flags).as_bool() {
        let error: WIN32_ERROR = GetLastError();
        error!("VirtualProtect PAGE_EXECUTE_READWRITE failed: {:?}", error);
        return Err(HookError::VirtualProtectFailed(error));
    }
    let new_value = new_address.wrapping_sub(call_address + 5); // +5 for the size of the call
    let rel32_ptr: *mut u32 = (call_address + 1) as _;
    debug!("Reading old rel32 at {:#08x}", rel32_ptr as usize);
    let old_rel32 = rel32_ptr.read_unaligned();
    debug!("Writing new rel32 at {:#08x}", rel32_ptr as usize);
    rel32_ptr.write_unaligned(new_value as _);
    debug!("Restoring page permissons");
    if !VirtualProtect(call_address as _, 5, old_flags, &mut old_flags).as_bool() {
        let error: WIN32_ERROR = GetLastError();
        error!("VirtualProtect restore failed: {:?}", error);
        return Err(HookError::VirtualProtectFailed(error));
    }

    Ok(CallRel32Hook {
        module,
        offset,
        old_rel32,
    })
}

impl Drop for CallRel32Hook {
    fn drop(&mut self) {
        unsafe {
            info!("Dropping {:?}", self);
            let call_base = GetModuleHandleA(self.module).unwrap();
            let call_address = call_base.0 as usize + self.offset;

            let mut old_flags: PAGE_PROTECTION_FLAGS = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(call_address as _, 8, PAGE_EXECUTE_READWRITE, &mut old_flags).as_bool() {
                let error: WIN32_ERROR = GetLastError();
                panic!("VirtualProtect PAGE_EXECUTE_READWRITE failed: {:?}", error);
            }
            let rel32_ptr: *mut u32 = (call_address + 1) as _;
            debug!("Patching rel32 at {:#016x}", rel32_ptr as usize);
            rel32_ptr.write_unaligned(self.old_rel32);
            if !VirtualProtect(call_address as _, 8, old_flags, &mut old_flags).as_bool() {
                let error: WIN32_ERROR = GetLastError();
                panic!("VirtualProtect restore failed: {:?}", error);
            }
        }
    }
}
