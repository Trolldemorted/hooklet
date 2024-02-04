use log::{debug, error, info, trace};
use std::thread;
use std::time::Duration;
use std::{mem::size_of, os::raw::c_void};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, WIN32_ERROR},
        System::Memory::{
            VirtualAlloc, VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PAGE_PROTECTION_FLAGS,
        },
    },
};

use crate::util;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    CodecaveSearchFailed,
    VirtualAllocFailed(WIN32_ERROR),
    VirtualProtectFailed(WIN32_ERROR),
    VirtualQueryFailed(WIN32_ERROR),
}

#[derive(Debug)]
pub struct CallRel32Hook {
    module: PCSTR,
    offset: usize,
    cave_address: *mut c_void,
    old_rel32: u32,
}

unsafe impl Send for CallRel32Hook {}

pub unsafe fn hook_call_rel32(module: PCSTR, offset: usize, new_address: u64) -> Result<CallRel32Hook, HookError> {
    let call_base = GetModuleHandleA(module).unwrap();
    let call_address = call_base.0 as usize + offset;
    info!("Hooking rel32 call at {call_address:#016x} to {new_address:#016x}");

    let shellcode = util::build_far_jump(new_address);
    let cave_address = alloc_codecave(call_address, shellcode.len())?;

    debug!("Writing shellcode to cave {:#016x}", cave_address as usize);
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), cave_address as _, shellcode.len());

    debug!("Patching {:#08x} to call cave {:#x}", call_address, cave_address as usize);
    let mut old_flags: PAGE_PROTECTION_FLAGS = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    if !VirtualProtect(call_address as _, 5, PAGE_EXECUTE_READWRITE, &mut old_flags).as_bool() {
        let error: WIN32_ERROR = GetLastError();
        error!("VirtualProtect PAGE_EXECUTE_READWRITE failed: {:?}", error);
        return Err(HookError::VirtualProtectFailed(error));
    }
    let new_value = cave_address.wrapping_sub(call_address + 5); // +5 for the size of the call
    let rel32_ptr: *mut u32 = (call_address + 1) as _;
    debug!("Patching rel32 at {:#016x}", rel32_ptr as usize);
    let old_rel32 = rel32_ptr.read_volatile();
    rel32_ptr.write_volatile(new_value as _);
    if !VirtualProtect(call_address as _, 5, old_flags, &mut old_flags).as_bool() {
        let error: WIN32_ERROR = GetLastError();
        error!("VirtualProtect restore failed: {:?}", error);
        return Err(HookError::VirtualProtectFailed(error));
    }

    Ok(CallRel32Hook {
        module,
        offset,
        cave_address,
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
            rel32_ptr.write_volatile(self.old_rel32);
            if !VirtualProtect(call_address as _, 8, old_flags, &mut old_flags).as_bool() {
                let error: WIN32_ERROR = GetLastError();
                panic!("VirtualProtect restore failed: {:?}", error);
            }

            // Wait a bit, so all threads in the cave can exit it before we free the cave
            thread::sleep(Duration::from_millis(10));

            debug!("Freeing cave {:#016x}", self.cave_address as u64);
            if !VirtualFree(self.cave_address, 0, MEM_RELEASE).as_bool() {
                let error: WIN32_ERROR = GetLastError();
                panic!("VirtualFree failed: {:?}", error);
            }
        }
    }
}

// Credits to https://stackoverflow.com/a/60921721/1569755
unsafe fn alloc_codecave(close_address: usize, size: usize) -> Result<*mut c_void, HookError> {
    let mut cave_address = close_address;
    let mut info: MEMORY_BASIC_INFORMATION;
    info = std::mem::zeroed();

    while cave_address - close_address < 0xffff_ffff {
        trace!("VirtualQuery {:#016x}", cave_address);
        let q = VirtualQuery(Some(cave_address as _), &mut info, size_of::<MEMORY_BASIC_INFORMATION>());
        if q == 0 {
            let error: WIN32_ERROR = GetLastError();
            error!("VirtualQuery {:#016x} failed: {:?}", close_address, error);
            return Err(HookError::VirtualQueryFailed(error));
        }

        if info.State == MEM_FREE {
            debug!("Found free memory for codecave at {:#016x}", cave_address);
            let cave = VirtualAlloc(Some(cave_address as _), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if cave.is_null() {
                let error: WIN32_ERROR = GetLastError();
                error!("VirtualAlloc {:#016x} failed: {:?}", close_address, error);
                return Err(HookError::VirtualAllocFailed(error));
            }
            trace!("Cave allocated at {:016x}", cave as usize);

            return Ok(cave);
        } else {
            trace!("VirtualQuery returned state {:?}", info.State)
        }

        cave_address += 0x100_0000;
    }

    error!("Could not find suitable allocatable space for code cave");
    Err(HookError::CodecaveSearchFailed)
}
