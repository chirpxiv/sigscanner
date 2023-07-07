// Dependencies

use std::{
	ptr,
	ffi::c_char
};

use sigscanner::scanning::{
	find_sig_cstr,
	get_pe_header,
	lookup_section_name,
	lookup_section_cstr
};

// Scanner exports

#[no_mangle]
unsafe extern "C" fn ScanMemory(start_addr: *const u8, size: usize, sig_ptr: *const c_char) -> *const u8 {
	find_sig_cstr(start_addr, size, sig_ptr)
}

#[no_mangle]
unsafe extern "C" fn ScanText(base_addr: *const u8, sig_ptr: *const c_char) -> *const u8 {
	if let Some(section) = lookup_section_name(base_addr, ".text") {
		let start = base_addr.offset(section.base as isize);
		find_sig_cstr(start, section.size as usize, sig_ptr)
	} else {
		ptr::null()
	}
}

#[no_mangle]
unsafe extern "C" fn ScanData(base_addr: *const u8, sig_ptr: *const c_char) -> *const u8 {
	if let Some(section) = lookup_section_name(base_addr, ".data") {
		let start = base_addr.offset(section.base as isize);
		find_sig_cstr(start, section.size as usize, sig_ptr)
	} else {
		ptr::null()
	}
}

// Section exports

#[no_mangle]
unsafe extern "C" fn GetSectionTable(base_addr: *const u8, ptr: *mut *const u8) -> u16 {
	let header = get_pe_header(base_addr);
	if !ptr.is_null() {
		*ptr = base_addr.add(header.get_sections_offset());
	}
	header.coff.section_ct
}

#[no_mangle]
unsafe extern "C" fn LookupSectionName(base_addr: *const u8, name: *const c_char) -> *const u8 {
	if let Some(section) = lookup_section_cstr(base_addr, name) {
		base_addr.add(section.base)
	} else {
		ptr::null()
	}
}