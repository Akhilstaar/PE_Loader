use core::ffi::c_void;
use winapi::um::winnt::IMAGE_DOS_HEADER;

pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

// I'm thinking to replace syscalls like GetProcAddress, 
// LoadLibraryA with direct assembly code, compiled using NASM. 
// No need to import dll's for calling those functions. 
// Thoughts ??

use crate::customloader::types::{
    GetProcAddress, LoadLibraryA, IMAGE_BASE_RELOCATION, IMAGE_DATA_DIRECTORY,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS64,
    IMAGE_SECTION_HEADER,
};

pub fn readname_from_addr(baseaddress: *const u8) -> String {
    let mut temp = Vec::new();

    unsafe {
        let mut ptr = baseaddress;
        while *ptr != 0 {
            temp.push(*ptr);
            ptr = ptr.add(1);
        }
    }
    temp.push(0); // null terminator, don't remove this else it won't work.
    String::from_utf8_lossy(&temp).to_string() // Finally, convert the buffer to a string
}

pub fn get_dos_header(image_ptr: *const c_void) -> *const IMAGE_DOS_HEADER {
    image_ptr as *const IMAGE_DOS_HEADER
}

pub fn get_nt_header(image_base_address: *const c_void, dos_header: *const IMAGE_DOS_HEADER,) -> *const c_void {
    let nt_header_address = unsafe {(image_base_address as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64};
    nt_header_address as *const c_void
}

fn total_sections(nt_header_address: *const c_void) -> u16 {
    unsafe {
        (*(nt_header_address as *const IMAGE_NT_HEADERS64)).FileHeader.NumberOfSections
    }
}

fn data_dir(ntheader: *const c_void) -> IMAGE_DATA_DIRECTORY {
    unsafe {
        (*(ntheader as *const IMAGE_NT_HEADERS64)).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
    }
}

pub fn write_sections(baseptr: *const c_void, buffer: Vec<u8>, ntheader: *const c_void, dosheader: *const IMAGE_DOS_HEADER,) {
    let e_lfanew = unsafe { (*dosheader).e_lfanew as usize };
    let nt_header_size = core::mem::size_of::<IMAGE_NT_HEADERS64>();
    let mut st_section_header = (baseptr as usize + e_lfanew + nt_header_size) as *const IMAGE_SECTION_HEADER;

    for _i in 0..total_sections(ntheader) {
        let section_header = unsafe { &*st_section_header };
        let section_start = section_header.PointerToRawData as usize;
        let section_end = section_start + section_header.SizeOfRawData as usize;
        let section_data = &buffer[section_start..section_end];

        println!( "Copying section {}", readname_from_addr(unsafe { &(*st_section_header).Name } as *const _) );

        unsafe {
            core::ptr::copy_nonoverlapping(section_data.as_ptr() as *const c_void,(baseptr as usize + section_header.VirtualAddress as usize) as *mut c_void,section_header.SizeOfRawData as usize,);
        }

        st_section_header = unsafe { st_section_header.add(1) };
    }
}

fn verifyntheader(ntheader: *const c_void) {
    println!("ntheader INFO :\n");
    let ntheader = unsafe { &(*(ntheader as *const IMAGE_NT_HEADERS64)) };
    println!("Signature: {:?}", ntheader.Signature);
    print!("File Header:\n");
    println!("Machine: {:?}", ntheader.FileHeader.Machine);
    println!("NumberOfSections: {:?}", ntheader.FileHeader.NumberOfSections);
    println!("TimeDateStamp: {:?}", ntheader.FileHeader.TimeDateStamp);
    println!("PointerToSymbolTable: {:?}", ntheader.FileHeader.PointerToSymbolTable);
    println!("NumberOfSymbols: {:?}", ntheader.FileHeader.NumberOfSymbols);
    println!("SizeOfOptionalHeader: {:?}", ntheader.FileHeader.SizeOfOptionalHeader);
    println!("Characteristics: {:?}", ntheader.FileHeader.Characteristics);
    print!("Optional Header:\n");
    println!("Magic: {:?}", ntheader.OptionalHeader.Magic);
    println!("MajorLinkerVersion: {:?}", ntheader.OptionalHeader.MajorLinkerVersion);
    println!("MinorLinkerVersion: {:?}", ntheader.OptionalHeader.MinorLinkerVersion);
    println!("SizeOfCode: {:?}", ntheader.OptionalHeader.SizeOfCode);
    println!(
        "SizeOfInitializedData: {:?}",
        ntheader.OptionalHeader.SizeOfInitializedData
    );
    println!(
        "SizeOfUninitializedData: {:?}",
        ntheader.OptionalHeader.SizeOfUninitializedData
    );
    println!("AddressOfEntryPoint: {:?}", ntheader.OptionalHeader.AddressOfEntryPoint);
    println!("BaseOfCode: {:?}", ntheader.OptionalHeader.BaseOfCode);
    // println!("ImageBase: {:?}", ntheader.OptionalHeader.ImageBase);
    println!("SectionAlignment: {:?}", ntheader.OptionalHeader.SectionAlignment);
    println!("FileAlignment: {:?}", ntheader.OptionalHeader.FileAlignment);
    println!("MajorOperatingSystemVersion: {:?}", ntheader.OptionalHeader.MajorOperatingSystemVersion);
    println!("MinorOperatingSystemVersion: {:?}", ntheader.OptionalHeader.MinorOperatingSystemVersion);
    println!("MajorImageVersion: {:?}", ntheader.OptionalHeader.MajorImageVersion);
    println!("MinorImageVersion: {:?}", ntheader.OptionalHeader.MinorImageVersion);
    println!("MajorSubsystemVersion: {:?}", ntheader.OptionalHeader.MajorSubsystemVersion);
    println!("MinorSubsystemVersion: {:?}", ntheader.OptionalHeader.MinorSubsystemVersion);
    println!("Win32VersionValue: {:?}", ntheader.OptionalHeader.Win32VersionValue);
    println!("SizeOfImage: {:?}", ntheader.OptionalHeader.SizeOfImage);
    println!("SizeOfHeaders: {:?}", ntheader.OptionalHeader.SizeOfHeaders);
    println!("CheckSum: {:?}", ntheader.OptionalHeader.CheckSum);
    println!("Subsystem: {:?}", ntheader.OptionalHeader.Subsystem);
    println!("DllCharacteristics: {:?}", ntheader.OptionalHeader.DllCharacteristics);
    // println!("SizeOfStackReserve: {:?}", ntheader.OptionalHeader.SizeOfStackReserve);
    // println!("SizeOfStackCommit: {:?}", ntheader.OptionalHeader.SizeOfStackCommit);
    // println!("SizeOfHeapReserve: {:?}", ntheader.OptionalHeader.SizeOfHeapReserve);
    // println!("SizeOfHeapCommit: {:?}", ntheader.OptionalHeader.SizeOfHeapCommit);
    println!("LoaderFlags: {:?}", ntheader.OptionalHeader.LoaderFlags);
    println!("NumberOfRvaAndSizes: {:?}", ntheader.OptionalHeader.NumberOfRvaAndSizes);
    print!("Data Directory:\n");
    println!("Export: {:?}", ntheader.OptionalHeader.DataDirectory[0]);
    println!("Import: {:?}", ntheader.OptionalHeader.DataDirectory[1]);
    println!("Resource: {:?}", ntheader.OptionalHeader.DataDirectory[2]);
    println!("Exception: {:?}", ntheader.OptionalHeader.DataDirectory[3]);
    println!("Security: {:?}", ntheader.OptionalHeader.DataDirectory[4]);
    println!("BaseRelocation: {:?}", ntheader.OptionalHeader.DataDirectory[5]);
    println!("Debug: {:?}", ntheader.OptionalHeader.DataDirectory[6]);
    println!("Architecture: {:?}", ntheader.OptionalHeader.DataDirectory[7]);
    println!("GlobalPtr: {:?}", ntheader.OptionalHeader.DataDirectory[8]);
    println!("TLS: {:?}", ntheader.OptionalHeader.DataDirectory[9]);
    println!("LoadConfig: {:?}", ntheader.OptionalHeader.DataDirectory[10]);
    println!("BoundImport: {:?}", ntheader.OptionalHeader.DataDirectory[11]);
    println!("IAT: {:?}", ntheader.OptionalHeader.DataDirectory[12]);
    println!("DelayImport: {:?}", ntheader.OptionalHeader.DataDirectory[13]);
    println!("CLR: {:?}", ntheader.OptionalHeader.DataDirectory[14]);
    println!("Reserved: {:?}", ntheader.OptionalHeader.DataDirectory[15]);

    println!("\nProbably loaded fine \n\\n\n")
}

pub fn validate_image_descriptor(original_first_thunk_ptr: *mut c_void) -> bool {
    unsafe {
        (*(original_first_thunk_ptr as *const IMAGE_IMPORT_DESCRIPTOR)).Name != 0
            && (*(original_first_thunk_ptr as *const IMAGE_IMPORT_DESCRIPTOR)).FirstThunk != 0
    }
}

pub fn write_import_table(baseptr: *const c_void, ntheader: *const c_void,) {
    verifyntheader(ntheader); // Check

    let import_dir = data_dir(ntheader);
    if import_dir.Size == 0 { return; } // No imports
    let mut original_first_thunk_ptr = baseptr as usize + import_dir.VirtualAddress as usize;
    
    println!("Import Directory: {:?}", import_dir);
    println!("First Thunk Ptr: {:?}", original_first_thunk_ptr);
    println!("Virtual Address: {:?}", import_dir.VirtualAddress);
    println!("Import Descriptor: {:?}", unsafe {
        (*(original_first_thunk_ptr as *const IMAGE_IMPORT_DESCRIPTOR)).Name
    });
    println!("First Thunk: {:?}", unsafe {
        (*(original_first_thunk_ptr as *const IMAGE_IMPORT_DESCRIPTOR)).FirstThunk
    });

    while validate_image_descriptor(original_first_thunk_ptr as *mut c_void){
        let mut import = unsafe { core::mem::zeroed::<IMAGE_IMPORT_DESCRIPTOR>() };
        unsafe {
            core::ptr::copy_nonoverlapping(
                original_first_thunk_ptr as *const u8,
                &mut import as *mut IMAGE_IMPORT_DESCRIPTOR as *mut u8,
                core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
            );
        }
        let dllname = readname_from_addr((baseptr as usize + import.Name as usize) as *const u8);
        print!("Loading dll : {}", dllname);

        // Load the DLL
        // TODO: Implement Loading of DLL natively
        let dllhandle = unsafe { LoadLibraryA(dllname.as_bytes().as_ptr() as *const u8) };
        print!("Loaded at {:?}\n", dllhandle);
        let mut thunkptr = unsafe {
            baseptr as usize + (import.Anonymous.OriginalFirstThunk as usize | import.Anonymous.Characteristics as usize)
        };
        let mut funcaddr_ptr = (baseptr as usize + import.FirstThunk as usize) as *mut usize;

        while unsafe { *(thunkptr as *const usize) } != 0 {
            let mut thunkdata: [u8; core::mem::size_of::<usize>()] = unsafe { core::mem::zeroed::<[u8; core::mem::size_of::<usize>()]>() };
            unsafe {
                core::ptr::copy_nonoverlapping(thunkptr as *const u8, &mut thunkdata as *mut u8,core::mem::size_of::<usize>(),);
            }
            let offset = usize::from_ne_bytes(thunkdata);
            // Read the function name
            let funcname = readname_from_addr((baseptr as usize + offset as usize + 2) as *const u8);
            
            if !funcname.is_empty() {
                // Get it's address
                let funcaddress = unsafe { GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const u8) };

                println!("Imported {}", funcname);
                // Write it's address
                unsafe { core::ptr::write(funcaddr_ptr, funcaddress as usize) };
            }
            funcaddr_ptr = ((funcaddr_ptr as usize) + core::mem::size_of::<usize>()) as *mut usize;
            thunkptr += core::mem::size_of::<usize>();
        }
        original_first_thunk_ptr += core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }
}

pub fn fix_base_relocations(image_base_ptr: *mut c_void, nt_header_ptr: *const c_void) {
    // final_address = image_base_ptr + reloc_entry_ptr + image_base_offset
    let nt_header = unsafe { &(*(nt_header_ptr as *const IMAGE_NT_HEADERS64)).OptionalHeader };
    let base_reloc_directory = &nt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if base_reloc_directory.Size == 0 { return; }

    let image_base = nt_header.ImageBase as usize;
    let image_base_offset = image_base_ptr as usize - image_base; 

    unsafe {
        // Initialize pointer to beginning of Base Relocation data
        let mut reloc_entry_ptr = (image_base_ptr as usize + base_reloc_directory.VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;
        while (*reloc_entry_ptr).SizeOfBlock != 0 {
            // Obtaining the pointer to start of relocation entries
            let num_entries = ((*reloc_entry_ptr).SizeOfBlock - std::mem::size_of::<IMAGE_BASE_RELOCATION>() as u32) / 2;
            let reloc_offset_ptr = (reloc_entry_ptr as *mut u8).add(std::mem::size_of::<IMAGE_BASE_RELOCATION>());
            let reloc_entries_slice = std::slice::from_raw_parts_mut(reloc_offset_ptr as *mut u16, num_entries as usize);

            // Begin Relocation
            for &reloc_entry in reloc_entries_slice.iter() {
                // Calculate final address to be fixed & replace
                let final_address = image_base_ptr as usize + (*reloc_entry_ptr).VirtualAddress as usize + (reloc_entry & 0x0fff) as usize;
                let original_address = std::ptr::read(final_address as *const usize);
                let fixed_address = (original_address + image_base_offset) as usize;
                std::ptr::write(final_address as *mut usize, fixed_address);
            }
            reloc_entry_ptr = (reloc_entry_ptr as *mut u8).add((*reloc_entry_ptr).SizeOfBlock as usize) as *mut IMAGE_BASE_RELOCATION;
        }
    }
    println!("Base Relocations Done !!");
}