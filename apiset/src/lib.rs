#![feature(pointer_byte_offsets)]
use std::arch::asm;
use windows::Win32::System::Threading::PEB;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

/// `PEB.ApiSetMap` is a pointer to this structure
#[repr(C)]
#[derive(Debug)]
pub struct ApiSetNamespace {
    /// Version of the API set map
    pub version: u32,

    /// Size of the API set map (usually .apiset section virtual size)
    size: u32,

    /// Flags including whether the map is sealed or not (?)
    flags: u32,

    /// Hash table entry count
    count: u32,

    /// Offset to the API set entry values
    entry_offset: u32,

    /// Offset to the API set entries hash indexes
    hash_offset: u32,

    /// Multiplier to use when computing hashes
    hash_factor: u32,
}

impl ApiSetNamespace {
    /// Get a pointer to the APIset namespace from the current PEB
    pub unsafe fn from_current_peb() -> &'static Self {
        let current_peb = get_current_peb();

        // The ApiSet namespace is found within the `PEB.ApiSetMap`
        let api_set: &ApiSetNamespace =
            &*((*current_peb).Reserved9[0] as *const _);

        api_set
    }

    /// Resolve a name to the host DLL
    pub fn resolve_to_host(
        &self,
        api_to_resolve: &str,
        parent_name: Option<&str>
    ) -> Option<String> {
        if api_to_resolve.len() >= 4 {
            let api_prefix = &api_to_resolve[0..4];
            if api_prefix == "api-" || api_prefix == "ext-" {
                // Compute word count of API set library without the suffix
                let (api_no_suffix, _) = api_to_resolve.rsplit_once("-")?;

                let resolved_entry =
                    unsafe { self.search_for_api_set(api_no_suffix)? };

                // If we have more than one returned entry
                if resolved_entry.value_count > 1 && parent_name.is_some() {
                    /*
                    let host_library_entry = self.search_for_api_set_host(
                        &resolved_entry,
                        parent_name.unwrap(),
                        parent_name.len()
                    );
                    */
                    unimplemented!();
                } else {
                    let result = unsafe {
                        resolved_entry
                            .values(self)[0]
                            .value(self)
                    };

                    return Some(result.into_string().ok()?);
                }
            }
        }
        None
    }

    /// Get an `ApiSetHashEntry` from the current namespace
    unsafe fn get_hash_entry(
        &self,
        hash_index: usize
    ) -> Option<&'static ApiSetHashEntry> {
        let ptr = (self as *const Self as *const ApiSetHashEntry)
            .byte_add(self.hash_offset as usize)
            .add(hash_index);
        Some(&*ptr)
    }

    /// Get an `ApiSetNamespaceEntry` from the current namespace
    unsafe fn get_namespace_entry(
        &self,
        hash_index: usize
    ) -> Option<&'static ApiSetNamespaceEntry> {
        let ptr = (self as *const Self as *const ApiSetNamespaceEntry)
            .byte_add(self.entry_offset as usize)
            .add(hash_index);
        Some(&*ptr)
    }

    /// Search for an API set entry
    pub unsafe fn search_for_api_set(
        &self,
        name_to_resolve: &str
    ) -> Option<&'static ApiSetNamespaceEntry> {
        // Compute hash key
        let hash_key: u32 = name_to_resolve
            .to_lowercase()
            .encode_utf16()
            .map(|cc| cc as u32)
            .map(|cc| {
                if cc.wrapping_sub(0x41) <= 0x19 {
                    cc + 0x20
                } else {
                    cc
                }
            })
            .fold(0, |hv, x| x.wrapping_add(self.hash_factor.wrapping_mul(hv)));
        
        // Look for matching hash key
        let mut api_set_entry_count = self.count - 1;
        let mut hash_counter = 0;
        let mut hash_index;
        loop {
            hash_index = (api_set_entry_count + hash_counter) >> 1;
            let hash_entry = self.get_hash_entry(hash_index as usize)?;
            if hash_key < hash_entry.hash {
                api_set_entry_count = hash_index - 1;

                if hash_counter > api_set_entry_count {
                    return None;
                }
                continue;
            }

            if hash_key <= hash_entry.hash {
                break;
            }

            hash_counter = hash_index + 1;

            if hash_counter > api_set_entry_count {
                return None;
            }
        }

        let found_entry = self.get_namespace_entry(
            self.get_hash_entry(hash_index as usize)?.index as usize
        )?;

        // Final check just to make sure there were collisions with another hash
        // bucket
        let value_name = found_entry.name(self)?
            .into_string().ok()?;

        if name_to_resolve == &value_name {
            Some(found_entry)
        } else {
            None
        }
    }
}

/// Hash table index
#[repr(C)]
struct ApiSetHashEntry {
    hash: u32,
    index: u32
}

/// Hash table value
#[repr(C)]
#[derive(Debug)]
pub struct ApiSetNamespaceEntry {
    /// Has the "sealed" flag in bit 0
    flags: u32,

    /// Offset to the API set library name (PWCHAR)
    name_offset: u32,

    /// Ignored
    name_length: u32,

    /// API set library name length
    hashed_length: u32,

    /// Offset to the resolved library (pointer to ApiSetValueEntry)
    value_offset: u32,

    /// Number of resolved libraries
    value_count: u32
}

impl ApiSetNamespaceEntry {
    /// Fetch 'name' of this entry
    unsafe fn name(
        &self,
        namespace: &ApiSetNamespace
    ) -> Option<OsString> {
        // Check if name length divisible by two
        if self.hashed_length % 2 != 0 {
            return None;
        }

        let ptr = (namespace as *const _ as *const u16)
            .byte_add(self.name_offset as usize);

        let source = unsafe {
            std::slice::from_raw_parts(
                ptr,
                self.hashed_length as usize / 2
            )
        };

        let os_string = OsString::from_wide(source);

        Some(os_string)
    }

    /// Get the `ApiSetValueEntry` values from this entry
    unsafe fn values(
        &self,
        namespace: &ApiSetNamespace
    ) -> &'static [ApiSetValueEntry] {
        let ptr = (namespace as *const _ as *const ApiSetValueEntry)
            .byte_add(self.value_offset as usize);

        let values = unsafe {
            std::slice::from_raw_parts(
                ptr,
                self.value_count as usize
            )
        };

        values
    }
}

/// Resolved library entry
#[repr(C)]
struct ApiSetValueEntry {
    /// Has the "sealed" flag in bit 0
    flags: u32,

    /// Offset to the API set library name (PWCHAR)
    name_offset: u32,

    /// API set library name length
    name_length: u32,

    /// Offset to the resolved library name (e.g. "ucrtbase.dll")
    value_offset: u32,

    /// Resolved library name length
    value_length: u32
}

impl ApiSetValueEntry {
    /// Get the 'value' string
    unsafe fn value(
        &self,
        namespace: &ApiSetNamespace
    ) -> OsString {
        let ptr = (namespace as *const _ as *const u16)
            .byte_add(self.value_offset as usize);

        let source = unsafe {
            std::slice::from_raw_parts(
                ptr,
                self.value_length as usize / 2
            )
        };

        OsString::from_wide(source)
    }
}

/// Get a pointer to the PEB of the current process
unsafe fn get_current_peb() -> *const PEB {
    let mut res: *const PEB;

    #[cfg(target_pointer_width="64")]
    asm!("mov {}, gs:[0x60]", out(reg) res);

    #[cfg(target_pointer_width="32")]
    asm!("mov {}, fs:[0x30]", out(reg) res);

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let api_set = unsafe { ApiSetNamespace::from_current_peb() };

        let host = api_set.resolve_to_host(
            "api-ms-win-core-crt-l1-1-0.dll",
            None
        );

        assert!(host == Some(String::from("ntdll.dll")));
    }
}
