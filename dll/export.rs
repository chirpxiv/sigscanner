// Dependencies

use std::{
	ptr,
	ffi::c_char
};

// Scanner exports

#[no_mangle]
unsafe extern "C" fn ScanMemory(start_addr: *const u8, size: usize, sig_ptr: *const c_char) -> *const u8 {
	sigscanner::scanning::find_sig_cstr(start_addr, size, sig_ptr)
}

#[no_mangle]
unsafe extern "C" fn ScanText(base_addr: *const u8, sig_ptr: *const c_char) -> *const u8 {
	if let Some(section) = sigscanner::module::lookup_section_name(base_addr, ".text") {
		let start = base_addr.offset(section.base as isize);
		sigscanner::scanning::find_sig_cstr(start, section.size as usize, sig_ptr)
	} else {
		ptr::null()
	}
}

#[no_mangle]
unsafe extern "C" fn ScanData(base_addr: *const u8, sig_ptr: *const c_char) -> *const u8 {
	if let Some(section) = sigscanner::module::lookup_section_name(base_addr, ".data") {
		let start = base_addr.offset(section.base as isize);
		sigscanner::scanning::find_sig_cstr(start, section.size as usize, sig_ptr)
	} else {
		ptr::null()
	}
}

// Module exports

#[no_mangle]
unsafe extern "C" fn FindSectionTable(base_addr: *const u8, ptr: *mut *const u8) -> u16 {
	let header = sigscanner::module::get_section_header(base_addr);
	*ptr = base_addr.offset(header.offset as isize);
	header.count
}

#[no_mangle]
unsafe extern "C" fn LookupSectionName(base_addr: *const u8, name: *const c_char) -> *const u8 {
	if let Some(section) = sigscanner::module::lookup_section_cstr(base_addr, name) {
		base_addr.offset(section.base as isize)
	} else {
		ptr::null()
	}
}