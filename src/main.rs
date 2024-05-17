use std::env;
use std::fs::File;
use std::io::Read;
mod customloader;
use core::ffi::c_void;
use customloader::functions::{
    is_dotnet_pe, fix_base_relocations, get_dos_header, get_nt_header,
    write_import_table, write_sections,
};
use customloader::types::{VirtualAlloc, IMAGE_NT_HEADERS64};
extern crate alloc;

pub const MEM_COMMIT: u32 = 0x1000;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// TODO: Verify if u32 type(changed on 10 March) is correct else change it back to i32.
pub fn get_image_size(buffer: &[u8]) -> usize {
    // Get the offset to the NT header
    let offset = u32::from_le_bytes(buffer[60..64].try_into().unwrap()) as usize;

    // Get the bit version from the buffer
    let bit = u16::from_le_bytes(
        buffer[offset + 4 + 20..offset + 4 + 20 + 2]
            .try_into()
            .unwrap(),
    );

    // Check the bit version and return image size
    match bit {
        523 | 267 => {
            let index = offset + 24 + 60 - 4;
            let size = u32::from_le_bytes(buffer[index..index + 4].try_into().unwrap()) as usize;
            size
        }
        _ => panic!("Invalid bit version"),
    }
}

pub fn get_headers_size(buffer: &[u8]) -> usize {
    // Check if buffer is large enough for MZ signature
    if buffer.len() < 2 || buffer[0] != b'M' || buffer[1] != b'Z' {
        panic!("Not a PE file (MZ signature not found)");
    }

    // Get the offset to the NT header
    let offset = if buffer.len() >= 64 {
        u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize
    } else {
        panic!("File size less than 64-bit offset");
    };

    // Check if buffer is large enough for the NT header
    if buffer.len() < offset + 4 + 20 + 2 {
        panic!("File size is less than required offset");
    }

    // Check the bit version and return the size of the headers
    match u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]) {
        523 | 267 => {
            let index = offset + 24 + 60;
            let headers_size =
                u32::from_le_bytes(buffer[index..index + 4].try_into().unwrap()) as usize;
            headers_size
        }
        _ => panic!("Invalid bit version"),
    }
}

unsafe fn execute_image(entrypoint: *const c_void) {
    // Just Calls the entry point
    let func: extern "C" fn() -> u32 = core::mem::transmute(entrypoint);
    func();
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }
    let file_name = &args[1];
    let file_path = std::path::Path::new(file_name);

    if file_path.is_file() {
        match File::open(file_path) {
            Ok(mut file) => {
                let mut data = Vec::new();
                if let Err(err) = file.read_to_end(&mut data) {
                    return Err(format!("Error reading file: {}", err));
                }
                println!("File Opened");

                if !is_dotnet_pe(&data) {
                    unsafe {
                        println!("Not a Dot net file.");
                        
                        // TODO:: add a function to check the device architecture before proocessing further.
                        
                        // Working with Headers //
                        let headerssize = get_headers_size(&data);
                        let imagesize = get_image_size(&data);
                        let dosheader = get_dos_header(data.as_ptr() as *const c_void);
                        let ntheader = get_nt_header(data.as_ptr() as *const c_void, dosheader);
                        
                        println!("Headers Size: {}", headerssize);
                        println!("Image Size: {}", imagesize);
                        println!("Dos Header Address: {:?}", dosheader);
                        println!("NT Header Address: {:?}", ntheader);
                        
                        // TODO:: Need to add section specific permissions instead of RWX.
                        let baseptr = VirtualAlloc(
                            core::ptr::null_mut(),
                            imagesize,
                            MEM_COMMIT,
                            PAGE_EXECUTE_READWRITE,
                        );

                        // Write the headers to the allocated memory
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr() as *const c_void,
                            baseptr,
                            headerssize,
                        );

                        // Working with sections, here //
                        println!("Writing Sections\n");
                        write_sections(baseptr, data.clone(), ntheader, dosheader);

                        // Write the import table to the allocated memory
                        println!("\n\nWriting Import Table\n");
                        write_import_table(baseptr, ntheader);

                        // Does what it says
                        println!("\nFixing Base Relocations\n");
                        fix_base_relocations(baseptr, ntheader);

                        let entrypoint = (baseptr as usize + (*(ntheader as *const IMAGE_NT_HEADERS64)).OptionalHeader.AddressOfEntryPoint as usize) as *const c_void;

                        // Executing it //
                        // Create a new thread to execute the image
                        println!("Executing !!!");
                        execute_image(entrypoint);

                        // Free the allocated memory of baseptr
                        let _ = baseptr;
                    };
                } else {
                    panic!(".net support not implemented yet 😅!")
                }

                Ok(())
            }
            Err(err) => {
                return Err(format!("Error opening file: {}", err));
            }
        }
    } else {
        return Err(format!("{} is not a file at specified location.", file_name));
    }
}