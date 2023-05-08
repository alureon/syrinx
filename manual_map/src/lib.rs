use pelite::pe64::{Pe, PeFile, imports::Import};
use winapi::shared::minwindef::LPVOID;
use winapi::um::winnt::{
    PROCESS_ALL_ACCESS,
    MEM_RESERVE,
    MEM_COMMIT,
    PAGE_READWRITE,
    PAGE_EXECUTE_READWRITE,
    PAGE_READONLY,
    PAGE_EXECUTE_READ,
    PAGE_NOACCESS,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_REL_BASED_DIR64,
    THREAD_ALL_ACCESS,
    PCONTEXT,
    CONTEXT_ALL
};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::{
    CreateRemoteThread,
    OpenProcess,
    SuspendThread,
    ResumeThread,
    OpenThread,
    GetThreadContext,
    SetThreadContext
};
use winapi::um::wow64apiset::IsWow64Process;
use winapi::um::memoryapi::{
    VirtualAllocEx,
    VirtualProtectEx,
    WriteProcessMemory
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot,
    Thread32First,
    Thread32Next,
    THREADENTRY32,
    TH32CS_SNAPTHREAD
};
use winapi::um::winbase::InitializeContext;
use thiserror::Error;

extern {
    /// Size of the assembly stub `dll_main_trampoline`
    static DLL_MAIN_TRAMPOLINE_SIZE: u64;

    /// The DllMain trampoline function, which will be copied into the target,
    /// and a thread will be created on it
    fn dll_main_trampoline(entry: u64);
}

/// Error type for manual mapping PE files
#[derive(Error, Debug)]
pub enum ManualMapError {
    #[error("Failed to open process")]
    OpenProcess,

    #[error("IsWow64Process failed")]
    IsWow64Process,

    #[error("The target process is not supported for injection")]
    TargetNotSupported,

    #[error("PeLite error: {0}")]
    PeLite(#[from] pelite::Error),

    #[error("Failed to allocate memory in the target process")]
    AllocationFailed,

    #[error("Failed to write image into target process")]
    WriteFailed,

    #[error("Failed changing page permissions in target process")]
    VirtualProtectEx,

    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("Failed to create thread in the target process")]
    ThreadFail,

    #[error("Failed to enumerate threads")]
    ThreadEnumerate,
}

/// Result type for manual mapping
pub type Result<T> = std::result::Result<T, ManualMapError>;

/// Manual map a PE file into the target process
/// Returns the base address of the manually mapped module
// TODO: Maybe we take a `Pe` trait object instead of `PeFile`
pub fn map(target_proc_id: u32, pe: &PeFile, hijack: bool) -> Result<usize> {
    // Attempt to open the process
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, target_proc_id) };

    if handle == INVALID_HANDLE_VALUE {
        return Err(ManualMapError::OpenProcess);
    }

    // Check process is running under WOW64 (if it is, then the target is)
    // 32-bit, and that means we don't support mapping to it
    let mut wow64 = 0i32;
    if unsafe { IsWow64Process(handle, &mut wow64) } == 0 {
        return Err(ManualMapError::IsWow64Process);
    }

    // If the target is running under WOW64 we cannot inject to it, bail
    if wow64 != 0 {
        return Err(ManualMapError::TargetNotSupported);
    }

    // 1. Allocate some memory in the target process, try to get it at the
    // program's requested base address
    let mut allocation = unsafe {
        VirtualAllocEx(
            handle, 
            pe.optional_header().ImageBase as *mut _,
            pe.optional_header().SizeOfImage as usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
            // PAGE_READWRITE
        )
    };

    // If we couldn't allocate at the base address, just give us any address,
    // and we'll rebase
    if allocation == std::ptr::null_mut() {
        allocation = unsafe {
            VirtualAllocEx(
                handle, 
                std::ptr::null_mut(),
                pe.optional_header().SizeOfImage as usize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
                // PAGE_READWRITE
            )
        };

        if allocation == std::ptr::null_mut() {
            // If we STILL couldn't allocate, then we failed to get an
            // allocation
            return Err(ManualMapError::AllocationFailed);
        }
    }

    println!("Allocated memory for image at {:#X}", allocation as usize);

    let mut image = vec![0u8; pe.optional_header().SizeOfImage as usize];

    // Write sections into image
    for section_header in pe.section_headers().image() {
        // Get underlying data of the section from the PE view
        let real_data = pe.get_section_bytes(section_header)?;

        let size = std::cmp::min(
            section_header.VirtualSize as usize,
            section_header.SizeOfRawData as usize
        );
        let virt_addr = section_header.VirtualAddress as usize;
        println!("Image length: {}", image.len());
        println!("Virt addr: {:#X}", virt_addr);
        println!("Ending: {}", virt_addr+size);
        println!("Length: {}", (virt_addr+size)-virt_addr);
        println!("Real data size: {}", real_data.len());
        println!("Size: {}", size);
        image[virt_addr..virt_addr+size].copy_from_slice(&real_data[..size]);
    }

    // Check if we need a rebase or not
    if pe.optional_header().ImageBase != (allocation as u64) {
        // Do base relocation table fixups
        pe.base_relocs()?.for_each(|virt_addr, ty| {
            let ty = ty as u16;
            match ty {
                IMAGE_REL_BASED_DIR64 => {
                    let virt_addr = virt_addr as usize;
                    let slice: [u8; 8] = image[virt_addr..virt_addr+8]
                        .try_into()
                        .expect("Could not convert to slice");
                    let value = u64::from_le_bytes(slice)
                        + allocation as u64;
                    image[virt_addr..virt_addr+8]
                        .copy_from_slice(&value.to_le_bytes());
                }
                _ => unimplemented!()
            }
        });
    }

    // Fix up imports
    // TODO
    resolve_imports(pe, &mut image)?;

    // Write the image into the target process
    let mut bytes_written: usize = 0;
    let result = unsafe {
        WriteProcessMemory(
            handle,
            allocation,
            image.as_ptr() as *const _,
            pe.optional_header().SizeOfImage as usize,
            &mut bytes_written
        )
    };

    if result == 0 {
        return Err(ManualMapError::WriteFailed);
    }

    // After writing the buffer into the target process, we'll fix up the
    // permissions for the sections accordingly
    if false {
        for section_header in pe.section_headers().image() {
            // Create section permissions
            let characteristics = section_header.Characteristics;
            let read = characteristics & IMAGE_SCN_MEM_READ != 0;
            let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
            let execute = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

            let protection = match (read, write, execute) {
                (true, true, true) => PAGE_EXECUTE_READWRITE,
                (true, false, false) => PAGE_READONLY,
                (true, false, true) => PAGE_EXECUTE_READ,
                (false, false, false) => PAGE_NOACCESS,
                (true, true, false) => PAGE_READWRITE,
                _ => unimplemented!()
            };

            let section_size = std::cmp::min(
                section_header.VirtualSize as usize,
                section_header.SizeOfRawData as usize
            );

            let mut old_protection: u32 = 0;

            let target_address =
                allocation as usize + section_header.VirtualAddress as usize;

            println!("Target: {:#X}", target_address);

            println!("Setting memory protection for {:#X}-{:#X} to {}",
                     target_address, target_address + section_size, protection);

            let result = unsafe {
                VirtualProtectEx(
                    handle,
                    target_address as *mut _,
                    section_size,
                    protection,
                    &mut old_protection
                )
            };

            if result == 0 {
                let last_error = unsafe { GetLastError() };
                println!("Failed changing page protections on section: {}",
                         last_error);
            }
        }
    }

    // Now create the thread to actually execute the entry point
    // Copy the trampoline into a local buffer
    let dll_main_trampoline_mem = unsafe {
        std::slice::from_raw_parts(
            dll_main_trampoline as *const u8,
            DLL_MAIN_TRAMPOLINE_SIZE as usize
        )
    };

    // Allocate memory for the trampoline
    let trampoline_addr = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            DLL_MAIN_TRAMPOLINE_SIZE as usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )
    };

    println!("Allocated memory for trampoline at {:#X}",
             trampoline_addr as usize);

    let mut bytes_written: usize = 0;
    unsafe {
        WriteProcessMemory(
            handle,
            trampoline_addr,
            dll_main_trampoline_mem.as_ptr() as *const _,
            dll_main_trampoline_mem.len(),
            &mut bytes_written
        );
    }

    // Make it executable
    let mut old_protection: u32 = 0;
    let result = unsafe {
        VirtualProtectEx(
            handle,
            trampoline_addr,
            DLL_MAIN_TRAMPOLINE_SIZE as usize,
            PAGE_EXECUTE_READ,
            &mut old_protection
        )
    };

    if result == 0 {
        let last_error = unsafe { GetLastError() };
        println!("Failed changing page protections on trampoline: {}",
                 last_error);
        return Err(ManualMapError::VirtualProtectEx);
    }

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    // Call it!
    let entry_point: usize = allocation as usize +
        pe.optional_header().AddressOfEntryPoint as usize;
    println!("Entry point target address: {:#X}", entry_point);

    type ThreadEntry = extern "system" fn(LPVOID) -> u32;

    if hijack {
        hijack_thread(
            target_proc_id,
            trampoline_addr as u64,
            Some(entry_point as u64)
        )?;
    } else {
        let result = unsafe {
            CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                Some(*(&trampoline_addr as *const _ as *const ThreadEntry)),
                entry_point as *mut _,
                0,
                std::ptr::null_mut()
            )
        };

        if result == std::ptr::null_mut() {
            return Err(ManualMapError::ThreadFail);
        }
    }

    Ok(allocation as usize)
}

/// Resolve imports for the PE file
fn resolve_imports(pe: &PeFile, buffer: &mut [u8]) -> Result<()> {
    /// Whitelisted modules don't need to be loaded into the process, because
    /// they're automatically loaded into every single Windows process' address
    /// space at the same address, therefore we can just use `LoadLibraryA` and
    /// `GetProcAddress` in our own address space to pull the addresses of the
    /// routines
    const WHITELISTED_MODULES: [&str; 3] = [
        "user32.dll",
        "ntdll.dll",
        "kernel32.dll"
    ];

    let imports = pe.imports()?;
    for desc in imports.iter() {
        println!("{:?}", desc);
        let dll_name = desc.dll_name()?;
        let dll_name_str = dll_name.to_str()?.to_lowercase();
        if WHITELISTED_MODULES.contains(&dll_name_str.as_str()) {
            let lib = unsafe { LoadLibraryA(dll_name.as_ptr() as *const _) };
            let first_thunk = desc.image().FirstThunk;

            for (idx, import) in desc.int()?.enumerate() {
                let target = match import {
                    Ok(Import::ByName { hint: _, name }) => {
                        (unsafe {
                            GetProcAddress(
                                lib,
                                name.as_ptr() as *const _
                            )
                        } as u64)
                    }
                    Ok(Import::ByOrdinal { .. }) => unimplemented!(),
                    _ => unimplemented!()
                };

                let patch = (first_thunk + (8 * idx as u32)) as usize;
                buffer[patch..patch+8].copy_from_slice(&target.to_le_bytes());
            }
        } else {
            unimplemented!();
        }
        println!("DLL name: {}", dll_name.to_str().unwrap());
    }
    Ok(())
}

/// Hijack a thread in the process and use it to spawn our entry point
fn hijack_thread(
    proc_id: u32,
    entry: u64,
    param: Option<u64>
) -> Result<()> {
    // Enumerate threads running in the process
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD,
            proc_id
        )
    };

    // Grab the first thread we find
    let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
    // TODO: try_into()?
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut result = unsafe { Thread32First(snapshot, &mut te) };

    loop {
        if result == 0 {
            return Err(ManualMapError::ThreadEnumerate);
        }

        if te.th32OwnerProcessID == proc_id {
            break;
        }

        result = unsafe { Thread32Next(snapshot, &mut te) };
    }

    // We've got a thread now, let's hijack it!
    let thread = unsafe {
        OpenThread(
            THREAD_ALL_ACCESS,
            0,
            te.th32ThreadID
        )
    };

    if result == 0 {
        panic!("Could not get thread");
    }

    // Allocate a CONTEXT structure
    let mut context_length: u32 = 0;
    unsafe {
        InitializeContext(
            std::ptr::null_mut(),
            CONTEXT_ALL,
            std::ptr::null_mut(),
            &mut context_length
        );
    }

    println!("Context required length: {}", context_length);

    // Allocate the context buffer
    let mut buffer = vec![0u8; context_length as usize];
    let mut context_ptr: PCONTEXT = std::ptr::null_mut();
    unsafe {
        InitializeContext(
            buffer.as_mut_ptr() as *mut _,
            CONTEXT_ALL,
            &mut context_ptr,
            &mut context_length
        );
    }

    if context_ptr == std::ptr::null_mut() {
        let last_error = unsafe { GetLastError() };
        panic!("Context was NULL: {}", last_error);
    }

    unsafe {
        SuspendThread(thread);

        let _result = GetThreadContext(thread, context_ptr);

        // Necessary or it won't set the full context
        (*context_ptr).ContextFlags = CONTEXT_ALL;

        // Modify the context
        // NOTE: On 64-bit, apparently we can ONLY set non-volatile registers.
        (*context_ptr).Rip = entry;

        // Sentinel value so that the trampoline knows we're running in hijack
        // mode
        (*context_ptr).Rsi = 0x1333337;

        if let Some(param) = param {
            (*context_ptr).Rbx = param;
        }

        // Update the context and resume the thread
        let _result = SetThreadContext(thread, context_ptr);

        ResumeThread(thread);
    }

    Ok(())
}

// This defines the trampoline which will be injected into the target to allow
// executing the entrrypoint of our injected DLL
std::arch::global_asm!("
.globl dll_main_trampoline
dll_main_trampoline:
nop
sub rsp, 0x28
cmp rsi, 0x1333337
je hijack_mode // This is encoded relative, verified

mov rax, rcx // Move the target function address into RAX
jmp cont // This is encoded relative, verified

hijack_mode:
mov rax, rbx // Move the target function address into RAX (rbx cuz threadhijack)

cont:
mov rcx, 0 // hinstDLL:   NULL (for now)
mov rdx, 1 // Reason:     1    (DLL_PROCESS_ATTACH)
mov r8, 0  // lpReserved: NULL
call rax
add rsp, 0x28
ret
dll_main_trampoline_end:

.globl DLL_MAIN_TRAMPOLINE_SIZE
DLL_MAIN_TRAMPOLINE_SIZE:
.8byte (dll_main_trampoline_end - dll_main_trampoline)
");
