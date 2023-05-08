use winapi::um::winuser::{MessageBoxA, MB_OK};
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::shared::minwindef::{HINSTANCE, LPVOID, DWORD};
use std::ffi::CString;

#[allow(non_snake_case)]
#[no_mangle]
unsafe extern "system" fn DllMain(
    _hmod: HINSTANCE,
    reason: DWORD,
    _reserved: LPVOID
) -> u32 {
    if reason == DLL_PROCESS_ATTACH {
        let message = CString::new("Hello world!")
            .expect("Could not create CString");
        MessageBoxA(
            std::ptr::null_mut(),
            message.as_ptr(),
            message.as_ptr(),
            MB_OK
        );
    }
    1
}

