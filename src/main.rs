use pelite::FileMap;
use pelite::pe64::{Pe, PeFile};
use anyhow::Result;
use clap::Parser;
use std::path::Path;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot,
    Process32First,
    Process32Next,
    PROCESSENTRY32,
    TH32CS_SNAPPROCESS
};
use winapi::um::handleapi::CloseHandle;
use std::ffi::CStr;

/// Command line arguments to this program
#[derive(Parser, Debug)]
struct Args {
    /// The PE file (should be a library) which will be loaded into the target
    /// process
    #[arg(short, long)]
    file: String,

    /// Target process name
    #[arg(long, group = "process")]
    process_name: Option<String>,

    /// Target process ID
    #[arg(long, group = "process")]
    process_id: Option<u32>
}

/// Find the ID of a process given its name
fn get_process_id_from_name(proc_name: &str) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    let mut pe: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    // Iterate the snapshot in order to find the desired process
    let result = unsafe { Process32First(snapshot, &mut pe) };
    if result == 0 {
        return None;
    }

    loop {
        let exe_name = unsafe { CStr::from_ptr(pe.szExeFile.as_ptr()) };
        if exe_name.to_bytes() == proc_name.as_bytes() {
            unsafe { CloseHandle(snapshot); }
            return Some(pe.th32ProcessID);
        }

        if unsafe { Process32Next(snapshot, &mut pe) } == 0 {
            break;
        }
    }

    unsafe { CloseHandle(snapshot); }

    None
}

fn main() -> Result<()> {
    let args = Args::parse();
    let path = Path::new(&args.file);

    let target_process_id = if let Some(proc_id) = args.process_id {
        proc_id
    } else {
        // Take the process name and find the ID from it
        let proc_name = args.process_name.unwrap();
        get_process_id_from_name(&proc_name)
            .expect("Could not find process")
    };

    println!("Target process ID: {}", target_process_id);

    if let Ok(map) = FileMap::open(path) {
        let pe = PeFile::from_bytes(&map)?;
        println!("{:#X}", pe.optional_header().ImageBase);
        manual_map::map(target_process_id, &pe, true)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
}
