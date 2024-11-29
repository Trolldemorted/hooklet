use std::fmt::Debug;
use std::ptr;

use log::{debug, error, info};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetModuleHandleW};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, WIN32_ERROR},
        System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    VirtualAllocFailed(WIN32_ERROR),
    VirtualProtectFailed(WIN32_ERROR),
    VirtualQueryFailed(WIN32_ERROR),
    GetModuleHandleFailed(WIN32_ERROR),
}

#[derive(Debug)]
pub struct CallRel32Hook {
    call_address: u32,
    old_rel32: u32,
    pub old_absolute: u32,
}

#[derive(Debug)]
pub struct FunctionPointerHook {
    fpointer_address: u32,
    pub old_absolute: u32,
}

#[derive(Debug)]
pub enum X86Rel32Type {
    Call,
    Jump,
}

unsafe impl Send for CallRel32Hook {}

unsafe impl Send for FunctionPointerHook {}

/// Hook an x86 call (e8) or jmp (e9) instruction.
/// 
/// * `offset`` - Offset of the instruction relative to the executable's base address
/// * `new_address` - Absolute address of the new target
pub unsafe fn hook_call_rel32(offset: u32, new_address: u32) -> Result<CallRel32Hook, HookError> {
    let call_base = match GetModuleHandleW(PCWSTR::from_raw(ptr::null())) {
        Ok(h) => h,
        Err(e) => {
            let error: WIN32_ERROR = GetLastError();
            error!("GetModuleHandleW failed: {:?} ({e}", error);
            return Err(HookError::GetModuleHandleFailed(error));
        }
    };
    let call_address = call_base.0 as u32 + offset;
    hook_call_rel32_inner(call_address, new_address)
}

pub unsafe fn hook_call_rel32_with_module<P: Into<HSTRING> + Debug>(module: P, offset: u32, new_address: u32) -> Result<CallRel32Hook, HookError> {
    let module = module.into();
    debug!("GetModuleHandleW {module:?}");
    let call_base = match GetModuleHandleW(&module) {
        Ok(h) => h,
        Err(e) => {
            let error: WIN32_ERROR = GetLastError();
            error!("GetModuleHandleW failed: {:?} ({e}", error);
            return Err(HookError::GetModuleHandleFailed(error));
        }
    };
    let call_address = call_base.0 as u32 + offset;
    hook_call_rel32_inner(call_address, new_address)
}

unsafe fn hook_call_rel32_inner(call_address: u32, new_address: u32) -> Result<CallRel32Hook, HookError> {
    info!("Hooking rel32 call at {call_address:#08x} to {new_address:#08x}");
    let new_value = new_address.wrapping_sub(call_address + 5); // +5 for the size of the call
    let old_rel32_bytes = replace_slice_rwx(call_address + 1, &new_value.to_le_bytes()).unwrap();
    let old_rel32 = u32::from_le_bytes(old_rel32_bytes);
    let old_absolute = get_absolute_from_rel32(call_address, old_rel32);

    Ok(CallRel32Hook {
        call_address,
        old_rel32,
        old_absolute,
    })
}

impl Drop for CallRel32Hook {
    fn drop(&mut self) {
        unsafe {
            info!("Dropping {:?}", self);
            replace_slice_rwx(self.call_address + 1, &self.old_rel32.to_le_bytes()).unwrap();
        }
    }
}

pub unsafe fn hook_function_pointer(offset: u32, new_address: u32) -> Result<FunctionPointerHook, HookError> {
    let module_base = match GetModuleHandleW(PCWSTR::from_raw(ptr::null())) {
        Ok(h) => h,
        Err(e) => {
            let error: WIN32_ERROR = GetLastError();
            error!("GetModuleHandleA failed: {:?} ({e}", error);
            return Err(HookError::GetModuleHandleFailed(error));
        }
    };
    let fpointer_address = module_base.0 as u32 + offset;
    hook_function_pointer_inner(fpointer_address, new_address)
}

pub unsafe fn hook_function_pointer_width_module(module: PCSTR, offset: u32, new_address: u32) -> Result<FunctionPointerHook, HookError> {
    debug!("GetModuleHandleA {module:?}");
    let module_base = match GetModuleHandleA(module) {
        Ok(h) => h,
        Err(e) => {
            let error: WIN32_ERROR = GetLastError();
            error!("GetModuleHandleA failed: {:?} ({e}", error);
            return Err(HookError::GetModuleHandleFailed(error));
        }
    };
    let fpointer_address = module_base.0 as u32 + offset;
    hook_function_pointer_inner(fpointer_address, new_address)
}

pub unsafe fn hook_function_pointer_inner(fpointer_address: u32, new_address: u32) -> Result<FunctionPointerHook, HookError> {
    info!("Hooking function pointer at {fpointer_address:#08x} to {new_address:#08x}");
    let old_absolute_bytes = replace_slice_rwx(fpointer_address, &new_address.to_le_bytes())?;
    let old_absolute = u32::from_le_bytes(old_absolute_bytes);

    Ok(FunctionPointerHook {
        fpointer_address,
        old_absolute,
    })
}

impl Drop for FunctionPointerHook {
    fn drop(&mut self) {
        unsafe {
            info!("Dropping {:?}", self);
            replace_slice_rwx(self.fpointer_address, &self.old_absolute.to_le_bytes()).unwrap();
        }
    }
}

/// Deploy a rel32 detour.
///
/// The page of the patch will be set to RWX while patching is in progress. This function does not yet check
/// whether the patch crosses a page boundary.
pub unsafe fn deploy_rel32_raw(patch_address: u32, target_address: u32, reltype: X86Rel32Type) -> Result<(), HookError> {
    let rel32 = get_rel32_from_absolute(patch_address, target_address);

    let mut patch: [u8; 5] = [0; 5];
    match reltype {
        X86Rel32Type::Call => patch[0] = 0xe8,
        X86Rel32Type::Jump => patch[0] = 0xe9,
    }
    patch[1..5].copy_from_slice(&rel32);

    replace_slice_rwx(patch_address, &patch)?;

    Ok(())
}

/// Calculate the rel32 component of x86 jump and call instructions.
///
/// Arguments:
///
/// * `patch_address`: The address of the new jump or call instruction
/// * `target_address`: The address the new jump or call will target
pub fn get_rel32_from_absolute(patch_address: u32, target_address: u32) -> [u8; 4] {
    let relative_address = target_address.wrapping_sub(patch_address).wrapping_sub(5);
    relative_address.to_le_bytes()
}

pub fn get_absolute_from_rel32(rel32_address: u32, rel32: u32) -> u32 {
    rel32_address.wrapping_add(rel32).wrapping_add(5)
}

pub unsafe fn replace_slice_rwx<const LEN: usize>(destination: u32, data: &[u8; LEN]) -> Result<[u8; LEN], HookError> {
    let destination_ptr: *mut u8 = destination as _;
    let mut old_data = [0; LEN];

    debug!("Setting page permissions to RWX");
    let mut old_flags: PAGE_PROTECTION_FLAGS = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    if !VirtualProtect(destination as _, LEN, PAGE_EXECUTE_READWRITE, &mut old_flags).as_bool() {
        let error: WIN32_ERROR = GetLastError();
        error!("VirtualProtect PAGE_EXECUTE_READWRITE failed: {:?}", error);
        return Err(HookError::VirtualProtectFailed(error));
    }

    debug!("Reading old bytes");
    destination_ptr.copy_to(old_data.as_mut_ptr(), LEN);

    debug!("Writing new bytes");
    destination_ptr.copy_from(data.as_ptr(), LEN);

    debug!("Setting page permissions to old value");
    if !VirtualProtect(destination as _, LEN, old_flags, &mut old_flags).as_bool() {
        let error: WIN32_ERROR = GetLastError();
        error!("VirtualProtect restore failed: {:?}", error);
        return Err(HookError::VirtualProtectFailed(error));
    }

    Ok(old_data)
}
